// .github/scripts/cla.js against a fake GitHub API (node --test tests/node).
'use strict';
const test = require('node:test');
const assert = require('node:assert');
const path = require('node:path');

const cla = require(path.join(__dirname, '..', '..', '.github', 'scripts', 'cla.js'));

function fake({ commits, signatures = null, comments = [] }) {
  const calls = { statuses: [], writes: [], created: [], updated: [] };
  let stored = signatures && { sha: 's1', content: Buffer.from(JSON.stringify({ signedContributors: signatures })).toString('base64') };
  const github = {
    paginate: async (fn, args) => (await fn(args)).data,
    rest: {
      pulls: {
        listCommits: async () => ({ data: commits }),
        get: async ({ pull_number: n }) => ({ data: { number: n, head: { sha: 'head1' } } }),
      },
      repos: {
        getContent: async () => {
          if (!stored) { const e = new Error('nf'); e.status = 404; throw e; }
          return { data: stored };
        },
        createOrUpdateFileContents: async (args) => { calls.writes.push(args); stored = { sha: 's2', content: args.content }; },
        createCommitStatus: async (args) => { calls.statuses.push(args); },
      },
      issues: {
        listComments: async () => ({ data: comments }),
        createComment: async (args) => { calls.created.push(args); comments.push({ id: 9, user: { login: 'github-actions[bot]' }, body: args.body }); },
        updateComment: async (args) => { calls.updated.push(args); },
      },
    },
  };
  return { github, calls, signed: () => stored && JSON.parse(Buffer.from(stored.content, 'base64').toString()).signedContributors };
}

const repo = { owner: 'osintph', repo: 'routemap' };
const opened = { eventName: 'pull_request_target', repo,
  payload: { action: 'opened', pull_request: { number: 7, head: { sha: 'head1' } } } };
const comment = (who, body) => ({ eventName: 'issue_comment', repo, payload: {
  issue: { number: 7, pull_request: {} }, repository: { id: 1 },
  comment: { id: 55, body, user: who, created_at: '2026-10-05T00:00:00Z' } } });
const alice = { id: 101, login: 'alice' };
const mallory = { id: 666, login: 'mallory' };

test('an unsigned author fails the CLA status and gets one comment', async () => {
  const f = fake({ commits: [{ author: alice }] });
  assert.strictEqual(await cla({ github: f.github, context: opened, documentUrl: 'u' }), 'unsigned');
  assert.deepStrictEqual(f.calls.statuses.map((s) => [s.context, s.state, s.sha]), [['CLA', 'failure', 'head1']]);
  assert.strictEqual(f.calls.created.length, 1);
  await cla({ github: f.github, context: opened, documentUrl: 'u' });
  assert.strictEqual(f.calls.created.length, 1, 'the comment is updated, not repeated');
});

test('the author signs by comment; the status turns green on the head commit', async () => {
  const f = fake({ commits: [{ author: alice }] });
  assert.strictEqual(await cla({ github: f.github, context: comment(alice, cla.SENTENCE), documentUrl: 'u' }), 'signed');
  assert.deepStrictEqual(f.signed().map((s) => s.id), [101]);
  assert.strictEqual(f.calls.statuses.at(-1).state, 'success');
  assert.strictEqual(f.calls.statuses.at(-1).sha, 'head1');
});

test('someone who is not a commit author cannot sign for the pull request', async () => {
  const f = fake({ commits: [{ author: alice }] });
  assert.strictEqual(await cla({ github: f.github, context: comment(mallory, cla.SENTENCE), documentUrl: 'u' }), 'unsigned');
  assert.strictEqual(f.calls.writes.length, 0);
});

test('existing signatures, the allowlist and unlinked authors', async () => {
  let f = fake({ commits: [{ author: alice }, { author: { id: 1, login: 'osintph' } }], signatures: [{ id: 101, name: 'alice' }] });
  assert.strictEqual(await cla({ github: f.github, context: opened, documentUrl: 'u' }), 'signed');
  f = fake({ commits: [{ author: null, commit: { author: { name: 'Nobody' } } }] });
  assert.strictEqual(await cla({ github: f.github, context: opened, documentUrl: 'u' }), 'unsigned');
  assert.match(f.calls.statuses[0].description, /Nobody/);
});

test('other comments and closed pull requests do nothing', async () => {
  const f = fake({ commits: [{ author: alice }] });
  assert.strictEqual(await cla({ github: f.github, context: comment(alice, 'lgtm'), documentUrl: 'u' }), 'ignored');
  const closed = { ...opened, payload: { ...opened.payload, action: 'closed' } };
  assert.strictEqual(await cla({ github: f.github, context: closed, documentUrl: 'u' }), 'closed');
  assert.strictEqual(f.calls.statuses.length, 0);
});
