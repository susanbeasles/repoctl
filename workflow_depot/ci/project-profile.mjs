import {existsSync, readFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {spawnSync} from 'node:child_process';
import {pathToFileURL} from 'node:url';
export function profile(root) {
  const commands=[];
  if(existsSync(resolve(root,'package.json'))) {
    const pkg=JSON.parse(readFileSync(resolve(root,'package.json'),'utf8'));
    if(!existsSync(resolve(root,'package-lock.json'))) throw Error('Node profile requires package-lock.json');
    for(const name of ['lint','typecheck','test','build']) {
      if(typeof pkg.scripts?.[name]!=='string'||!pkg.scripts[name].trim()) throw Error(`Node profile requires reviewed ${name} script`);
    }
    commands.push(['npm','ci','--ignore-scripts','--no-audit','--no-fund']);
    for(const name of ['lint','typecheck','test','build']) commands.push(['npm','run',name]);
  }
  if(existsSync(resolve(root,'pyproject.toml'))) {
    // Runner choice is explicit; existing unittest/pytest commands remain intact.
    const policy=JSON.parse(readFileSync(resolve(root,'.workflow-depot-quality.json'),'utf8'));
    for(const key of ['pythonInstall','pythonLint','pythonTypes','pythonTests','pythonBuild']) {
      const argv=policy[key];
      if(!Array.isArray(argv)||!argv.length||argv.some(x=>typeof x!=='string'||!x||x.includes('\0'))) throw Error(`Missing reviewed ${key} argv`);
      commands.push(argv);
    }
  }
  if(!commands.length) throw Error('No configured supported project quality profile');
  return commands;
}
export function candidate(env) {
  if(env.GITHUB_EVENT_NAME!=='push'||!/^refs\/heads\/int\/[^\s]+$/.test(env.GITHUB_REF||'')||!/^[a-f0-9]{40}$/.test(env.GITHUB_SHA||'')) throw Error('Quality/build requires exact integration push candidate');
}
if(process.argv[1] && import.meta.url===pathToFileURL(resolve(process.argv[1])).href) {
  candidate(process.env);
  const root=resolve(process.argv[2]||'src');
  const commands=profile(root); // Validate all requirements before executing any tooling.
  const env={PATH:process.env.PATH,HOME:process.env.HOME,CI:'true',LANG:'C.UTF-8'};
  for(const argv of commands) {
    const result=spawnSync(argv[0],argv.slice(1),{cwd:root,env,stdio:'inherit',shell:false});
    if(result.error||result.status!==0) throw Error(`Quality command failed: ${argv[0]} ${argv.slice(1).join(' ')}`);
  }
}
