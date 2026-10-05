// The Contributor Licence Agreement check for pull requests (CLA.md).
//
// Run by .github/workflows/cla.yml through actions/github-script; it replaces
// the archived contributor-assistant action (RM-04). It never checks out or
// runs the pull request's code. Signatures stay in this repository, on the
// "cla-signatures" branch (signatures/v1/cla.json, the same format as before).
// The verdict is a commit status named "CLA" on the pull request's head commit,
// the required check on main. A signature posted as a comment sets that status
// directly, so the workflow needs no right to start other workflow runs.
'use strict';

const SENTENCE = 'I have read the CLA Document and I hereby sign the CLA';
const MARKER = '<!-- routemap-cla -->';
const BRANCH = 'cla-signatures';
const PATH = 'signatures/v1/cla.json';
const ALLOW = new Set(['osintph', 'dependabot[bot]', 'github-actions[bot]']);

async function loadSignatures(github, owner, repo) {
  try {
    const { data } = await github.rest.repos.getContent({ owner, repo, path: PATH, ref: BRANCH });
    const parsed = JSON.parse(Buffer.from(data.content, 'base64').toString('utf8'));
    return { sha: data.sha, list: Array.isArray(parsed.signedContributors) ? parsed.signedContributors : [] };
  } catch (error) {
    if (error.status === 404) return { sha: undefined, list: [] };
    throw error;
  }
}

// The pull request's commit authors: GitHub accounts by id, and the names of
// authors with no GitHub account (who cannot sign until their email is linked).
async function commitAuthors(github, owner, repo, number) {
  const commits = await github.paginate(github.rest.pulls.listCommits,
    { owner, repo, pull_number: number, per_page: 100 });
  const people = new Map();
  const unlinked = new Set();
  for (const c of commits) {
    if (c.author && c.author.id) people.set(c.author.id, c.author.login);
    else unlinked.add((c.commit && c.commit.author && c.commit.author.name) || 'unknown');
  }
  return { people, unlinked };
}

async function upsertComment(github, owner, repo, number, body) {
  const comments = await github.paginate(github.rest.issues.listComments,
    { owner, repo, issue_number: number, per_page: 100 });
  const mine = comments.find((c) => c.user && c.user.login === 'github-actions[bot]'
    && (c.body || '').includes(MARKER));
  const text = `${MARKER}\n${body}`;
  if (mine) {
    if (mine.body !== text) await github.rest.issues.updateComment({ owner, repo, comment_id: mine.id, body: text });
  } else {
    await github.rest.issues.createComment({ owner, repo, issue_number: number, body: text });
  }
}

module.exports = async function cla({ github, context, documentUrl }) {
  const { owner, repo } = context.repo;
  let pr;
  let body = '';
  if (context.eventName === 'pull_request_target') {
    if (context.payload.action === 'closed') return 'closed';
    pr = context.payload.pull_request;
  } else if (context.eventName === 'issue_comment') {
    if (!context.payload.issue || !context.payload.issue.pull_request) return 'not a pull request';
    body = (context.payload.comment.body || '').trim();
    if (body !== SENTENCE && body !== 'recheck') return 'ignored';
    pr = (await github.rest.pulls.get({ owner, repo, pull_number: context.payload.issue.number })).data;
  } else {
    return 'ignored';
  }

  const { people, unlinked } = await commitAuthors(github, owner, repo, pr.number);
  const signatures = await loadSignatures(github, owner, repo);
  const signed = new Set(signatures.list.map((s) => s.id));

  if (body === SENTENCE) {
    const who = context.payload.comment.user;
    // Only an author of the pull request's commits signs, and only once.
    if (people.has(who.id) && !signed.has(who.id)) {
      signatures.list.push({
        name: who.login, id: who.id, comment_id: context.payload.comment.id,
        created_at: context.payload.comment.created_at, repoId: context.payload.repository.id,
        pullRequestNo: pr.number,
      });
      const content = Buffer.from(`${JSON.stringify({ signedContributors: signatures.list }, null, 2)}\n`)
        .toString('base64');
      await github.rest.repos.createOrUpdateFileContents({
        owner, repo, path: PATH, branch: BRANCH, sha: signatures.sha, content,
        message: `CLA signed by ${who.login} in #${pr.number}`,
      });
      signed.add(who.id);
    }
  }

  const missing = [...people].filter(([id, login]) => !ALLOW.has(login) && !signed.has(id)).map(([, login]) => login);
  const ok = missing.length === 0 && unlinked.size === 0;
  const waiting = [...missing.map((l) => `@${l}`), ...[...unlinked].map((n) => `${n} (no GitHub account)`)];
  await github.rest.repos.createCommitStatus({
    owner, repo, sha: pr.head.sha, context: 'CLA', state: ok ? 'success' : 'failure',
    description: (ok ? 'All authors have signed the CLA' : `Not signed yet: ${waiting.join(', ')}`).slice(0, 140),
  });
  if (!ok) {
    await upsertComment(github, owner, repo, pr.number,
      'Thank you for your pull request. Before it can be considered, each author needs to sign the '
      + `[Contributor Licence Agreement](${documentUrl}) once, by posting this sentence as a comment:\n\n`
      + `> ${SENTENCE}\n\nWaiting for: ${waiting.join(', ')}. Please also note that contributions `
      + 'may be declined (see CONTRIBUTING.md).'
      + (unlinked.size ? ' A commit whose author email is not linked to a GitHub account cannot be '
        + 'signed for; link the email to your account or amend the commit.' : ''));
  } else if ([...people.values()].some((login) => !ALLOW.has(login))) {
    await upsertComment(github, owner, repo, pr.number, 'All authors have signed the CLA. Thank you.');
  }
  return ok ? 'signed' : 'unsigned';
};

module.exports.SENTENCE = SENTENCE;
