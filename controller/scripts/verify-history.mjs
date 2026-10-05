import {execFileSync} from 'node:child_process';
export function verifyHistory(before, after, git = (...args) => execFileSync('git', args, {encoding:'utf8'}).trim()) {
  const sha = /^[a-f0-9]{40}(?:[a-f0-9]{24})?$/;
  if (![before,after].every(value => sha.test(value) && !/^0+$/.test(value))) throw new Error('Missing trusted previous/current commit; refuse unanchored history');
  const parents = git('show','-s','--format=%P',after).split(' ');
  if (parents.length !== 1 || parents[0] !== before) throw new Error('Promotion must append exactly one commit to the previous main tip');
  git('merge-base','--is-ancestor',before,after);
  return {before,after,appendOnly:true};
}
if (process.argv[1]?.endsWith('/verify-history.mjs')) {
  try {console.log(JSON.stringify(verifyHistory(process.env.REPOCTL_BEFORE,process.env.REPOCTL_AFTER)));}
  catch(error){console.error(error.message);process.exitCode=1;}
}
