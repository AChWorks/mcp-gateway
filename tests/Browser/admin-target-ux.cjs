'use strict';
// Isolated, loopback-only Laravel fixture. Never exercise real Targets.
const assert = require('node:assert/strict');
const { chromium } = require('playwright');
const base = process.env.GATEWAY_BROWSER_BASE_URL;
if (!/^http:\/\/127\.0\.0\.1:\d{2,5}$/.test(base || '')) throw Error('Local fixture only');
const pass = x => console.log('PASS: '+x);
const entry = async (page,role='owner') => {
  const res = await page.goto(base+'/__browser__/experience/'+role);
  assert.equal(res.status(),200);
};
const summary = page => page.locator('#target-create-form').evaluate(f => ({
  route:f.querySelector('#ssh_mode').value,
  manual:!f.querySelector('[data-ssh-reverse-route]').hidden,
  managed:!f.querySelector('[data-ssh-managed]').hidden,
  standard:!f.querySelector('[data-ssh-standard]').hidden,
  action:new URL(f.action).pathname,
  dirty:f.dataset.adminDirty==='true',
  submitDisabled:f.querySelector('[data-target-submit]').disabled,
}));
(async () => {
  const browser=await chromium.launch({headless:true});
  try {
    const context=await browser.newContext({viewport:{width:1440,height:950}});
    const page=await context.newPage();const jsErrors=[];
    page.on('pageerror',e=>jsErrors.push(e.message));
    await entry(page);
    await page.goto(base+'/admin/targets/create?connector_type=ssh_direct');
    assert.deepEqual(await summary(page),{
      route:'direct',manual:false,managed:false,standard:true,action:'/admin/targets',dirty:false,submitDisabled:false});
    await page.locator('#ssh_mode').focus();
    await page.keyboard.press('ArrowDown');
    const managed=await summary(page);
    assert.deepEqual(managed,{route:'managed',manual:false,managed:true,standard:false,
      action:'/admin/targets/managed-reverse',dirty:true,submitDisabled:true});
    await page.keyboard.press('ArrowDown');
    const manual=await summary(page);
    assert.equal(manual.route,'manual');assert.equal(manual.manual,true);
    assert.equal(manual.managed,false);
    assert.equal(await page.locator('[data-ssh-route-value]').inputValue(),'reverse');
    await page.keyboard.press('Home');
    assert.equal((await summary(page)).route,'direct');
    assert.equal((await summary(page)).dirty,false);
    pass('SSH mode, action, visibility, ready gate, true edit and revert');
    await page.locator('#target_id').fill('real-draft');
    assert.equal((await summary(page)).dirty,true);
    await page.locator('#target_id').fill('');
    assert.equal((await summary(page)).dirty,false);
    await page.evaluate(()=>{
      const id=document.querySelector('#target_id');
      id.value='owner@example.test';
      id.dispatchEvent(new Event('input',{bubbles:true}));
    });
    await page.locator('#display_name').focus();
    assert.equal(await page.locator('#target_id').inputValue(),'');
    assert.equal((await summary(page)).dirty,false);
    pass('passive technical-id autofill rejected, real typed draft retained');
    await page.goto(base+'/admin/users/create');
    let warns=0;
    page.on('dialog', async dialog => {warns++;await dialog.dismiss();});
    await page.evaluate(()=>{
      const field=document.querySelector('#name');field.value='owner@example.test';
      field.dispatchEvent(new Event('change',{bubbles:true}));
    });
    await page.getByRole('link',{name:'Back to users'}).click();
    await page.waitForURL('**/admin/users');
    assert.equal(warns,0);
    assert.equal(new URL(page.url()).pathname,'/admin/users');
    await page.goto(base+'/admin/users/create');
    await page.locator('#name').fill('intended-name');
    await page.getByRole('link',{name:'Back to users'}).click();
    assert.equal(warns,1);
    assert.equal(new URL(page.url()).pathname,'/admin/users/create');
    await page.locator('#name').fill('');
    await page.getByRole('link',{name:'Back to users'}).click();
    await page.waitForURL('**/admin/users');
    assert.equal(warns,1);
    assert.equal(new URL(page.url()).pathname,'/admin/users');
    pass('User Name passive autofill vs edit, navigation warning, revert');
    await page.goto(base+'/admin/users/create');
    const protectedSubmit=await page.evaluate(()=>{
      const form=document.querySelector('[data-user-role-form]');
      const name=form.querySelector('#name'),pw=form.querySelector('[name=current_password]');
      name.value='owner@example.test';pw.value='passive-autofilled-password';
      form.noValidate=true;form.requestSubmit();
      return {name:name.value,pw:pw.value};
    });
    assert.deepEqual(protectedSubmit,{name:'',pw:''});
    pass('passively autofilled Owner password and Name cannot submit');

    // Persist only a disabled Gateway configuration on the disposable fixture.
    // No SSHD/systemd or public endpoint is contacted.
    const algorithm=Buffer.from('ssh-ed25519');
    const hostKey=Buffer.concat([
      Buffer.from([0,0,0,algorithm.length]),algorithm,
      Buffer.from([0,0,0,32]),Buffer.alloc(32,33),
    ]);
    await page.goto(base+'/admin/settings/reverse-ssh');
    if (await page.locator('#reverse_control_host').count() === 0) {
      await page.getByRole('link',{name:'Edit settings'}).click();
      await page.locator('#reverse_control_host').waitFor();
    }
    await page.locator('#reverse_control_host').fill('gateway.example.test');
    await page.locator('#reverse_control_port').fill('7770');
    await page.locator('#reverse_control_user').fill('mcp-reverse');
    await page.locator('#reverse_host_key').fill('ssh-ed25519 '+hostKey.toString('base64'));
    await page.locator('#reverse_owner_password').fill('isolated-browser-password');
    await page.getByRole('button',{name:'Save settings'}).click();
    await page.getByRole('link',{name:'Edit settings'}).waitFor();
    assert.equal(await page.locator('#reverse_control_host').count(),0);
    assert.ok(await page.getByText('Pinned control SSHD fingerprint').count()>0);
    await page.getByRole('link',{name:'Edit settings'}).click();
    await page.locator('#reverse_control_host').waitFor();
    assert.equal(await page.locator('#reverse_control_host').inputValue(),'gateway.example.test');
    await page.getByRole('link',{name:'Cancel editing'}).click();
    await page.getByRole('link',{name:'Edit settings'}).waitFor();
    assert.equal(await page.locator('#reverse_control_host').count(),0);
    pass('real disabled global configuration saved -> summary -> Edit -> Cancel');

    await page.goto(base+'/admin/targets/create?connector_type=ssh_direct&ssh_mode=managed');
    for(const width of [360,390,768,1440]){
      for(const dark of [false,true]){
        for(const rtl of [false,true]){
          await page.setViewportSize({width,height:950});
          await page.emulateMedia({colorScheme:dark?'dark':'light'});
          await page.evaluate(dir=>{document.documentElement.dir=dir;},rtl?'rtl':'ltr');
          const bounds=await page.evaluate(()=>{
            const rect=x=>{const r=x.getBoundingClientRect();return {left:r.left,right:r.right,width:r.width};};
            return {overflow:document.documentElement.scrollWidth-document.documentElement.clientWidth,
              panel:rect(document.querySelector('.target-enrollment')),
              form:rect(document.querySelector('#target-create-form'))};
          });
          assert.ok(bounds.overflow<=1,JSON.stringify({width,dark,rtl,bounds}));
          assert.ok(bounds.form.left>=bounds.panel.left-2 &&
            bounds.form.right<=bounds.panel.right+2,JSON.stringify({width,dark,rtl,bounds}));
        }
      }
    }
    pass('shared form geometry: phone/tablet/desktop, light/dark, RTL/LTR');

    const nojs=await browser.newContext({javaScriptEnabled:false,viewport:{width:390,height:950}});
    const plain=await nojs.newPage();
    await entry(plain);
    let res=await plain.goto(base+'/admin/targets/create?connector_type=ssh_direct&ssh_mode=managed');
    assert.equal(res.status(),200);
    assert.ok(await plain.locator('noscript a[href*="ssh_mode=manual"]').count()>0);
    assert.equal(new URL(await plain.locator('#target-create-form').getAttribute('action'),base).pathname,
      '/admin/targets/managed-reverse');
    res=await plain.goto(base+'/admin/targets/create?connector_type=ssh_direct&ssh_mode=manual');
    assert.equal(res.status(),200);
    assert.ok(await plain.locator('#ssh_reverse_port').isEnabled());
    await nojs.close();
    pass('no-JS canonical connection-mode links and correct server-side action');

    const other=await browser.newContext();
    const viewer=await other.newPage();
    await entry(viewer,'viewer');
    const denied=await viewer.goto(base+'/admin/targets/create?connector_type=ssh_direct&ssh_mode=managed');
    assert.equal(denied.status(),403);
    await other.close();
    pass('non-Owner cannot select Managed Reverse through direct URL');
    assert.deepEqual(jsErrors,[]);
    await context.close();
  } finally {await browser.close();}
})().catch(e=>{console.error(e.stack||String(e));process.exitCode=1;});
