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
    await page.goto(base+'/admin/targets/create');
    assert.equal(await page.locator('[data-target-ssh-shortcuts]').isVisible(),true);
    const startingUrl=page.url();
    await page.getByRole('link',{name:'Managed Reverse SSH',exact:true}).click();
    assert.equal(page.url(),startingUrl,'JavaScript shortcut must select within this form without navigation');
    assert.equal((await summary(page)).route,'managed');
    assert.equal((await summary(page)).action,'/admin/targets/managed-reverse');
    assert.equal(await page.locator('[data-target-ssh-shortcuts]').isVisible(),false);
    assert.equal(await page.evaluate(()=>document.activeElement?.id),'target_id');
    pass('Owner sees Managed Reverse from initial Add Target and selects it in-place');
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
    // An untrusted select change without preceding human interaction must
    // not manufacture an unsaved-change warning (R4).
    await page.locator('#target_id').focus();
    await page.locator('#ssh_mode').click();
    await page.evaluate(() => {
      const select=document.querySelector('#ssh_mode');
      select.value='managed';
      select.dispatchEvent(new Event('change',{bubbles:true}));
    });
    assert.equal((await summary(page)).route,'managed');
    assert.equal((await summary(page)).dirty,false);
    await page.evaluate(() => {
      const select=document.querySelector('#ssh_mode');
      select.value='direct';
      select.dispatchEvent(new Event('change',{bubbles:true}));
    });
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
      // Let the installed document-level Admin guard process submit first;
      // then prevent this synthetic probe from sending a real native POST.
      // Without this, the pending POST may race the next page.goto.
      form.noValidate=true;
      let prevented=false;
      document.addEventListener('submit',event=>{
        if(event.target===form) {
          prevented=event.defaultPrevented;
          event.preventDefault();
        }
      },{once:true});
      form.requestSubmit();
      return {name:name.value,prevented};
    });
    assert.deepEqual(protectedSubmit,{name:'',prevented:true});
    pass('passively filled password alone cannot submit; technical Name restored');

    // Test the actual two Owner-only revoke forms in a local fixture.
    const fixtureResult=await page.request.get(base+'/__browser__/owner-revocation-forms');
    assert.equal(fixtureResult.status(),200);
    const revokeUrls=await fixtureResult.json();
    for (const [kind,url,label] of [
      ['OAuth',revokeUrls.oauth,'Revoke this grant'],
      ['WordPress',revokeUrls.publishing,'Revoke grant'],
    ]) {
      await page.goto(url);
      const button=page.getByRole('button',{name:label,exact:true}).first();
      const form=button.locator('xpath=ancestor::form');
      const ownerPassword=form.locator('input[name="current_password"]');
      assert.equal(await ownerPassword.getAttribute('data-admin-requires-intent'),'');
      const endpoint=new URL(await form.getAttribute('action')).pathname;
      let submitted=0;
      const track=request=>{
        if(request.method()==='POST' && new URL(request.url()).pathname===endpoint) submitted++;
      };
      page.on('request',track);
      const consent=form.locator('[data-admin-owner-approval-input]');
      assert.equal(await consent.count(),1,kind+' requires shared explicit Owner approval');
      assert.match(await consent.getAttribute('type'),/checkbox/);
      assert.ok((await consent.locator('xpath=parent::label').innerText()).includes('I confirm'),
        kind+' confirmation must have a descriptive accessible label');
      for (const width of [360,390,768]) {
        await page.setViewportSize({width,height:900});
        for (const dir of ['ltr','rtl']) {
          await page.evaluate(direction=>{document.documentElement.dir=direction;},dir);
          const geometry=await form.locator('.admin-owner-approval').evaluate(node=>({
            width:node.clientWidth,scrollWidth:node.scrollWidth,height:node.getBoundingClientRect().height,
            visible:getComputedStyle(node).display!=='none',
          }));
          assert.equal(geometry.visible,true,kind+' Owner confirmation hidden at '+width+'/'+dir);
          assert.ok(geometry.scrollWidth<=geometry.width+1,
            kind+' Owner confirmation text overflows at '+width+'/'+dir+': '+JSON.stringify(geometry));
          assert.ok(geometry.height>=40,
            kind+' Owner confirmation target too small at '+width+'/'+dir);
        }
      }
      await page.setViewportSize({width:1440,height:950});
      await page.evaluate(()=>{document.documentElement.dir='ltr';});
      await ownerPassword.evaluate(control=>{control.value='passive-fixture-value';});
      await ownerPassword.click();
      assert.equal(await ownerPassword.inputValue(),'passive-fixture-value');
      await button.click();
      assert.equal(submitted,0,kind+' passive pre-click fill was submitted');
      assert.equal(await form.locator('.admin-owner-approval + .field-error').isVisible(),true);
      // Restored checkbox state and synthetic change cannot establish consent.
      await consent.evaluate(control=>{
        control.checked=true;
        control.dispatchEvent(new Event('change',{bubbles:true}));
      });
      await button.click();
      assert.equal(submitted,0,kind+' synthetic checkbox change bypassed Owner consent');
      assert.equal(await consent.isChecked(),false);

      // A real browser-generated input event is NOT evidence of a deliberate
      // password-manager choice. Playwright fill exercises the native event
      // path without claiming to simulate a particular password manager.
      await ownerPassword.fill('isolated-browser-password');
      await button.click();
      assert.equal(submitted,0,kind+' native input event bypassed explicit approval');

      // Both typing and paste still enter valid credentials. A separate
      // accessible checkbox marks the Owner's decision to use that value.
      await ownerPassword.click();
      if(kind==='OAuth') {
        await ownerPassword.fill('');
        await page.keyboard.type('isolated-browser-password');
      } else {
        await ownerPassword.fill('');
        await context.grantPermissions(['clipboard-read','clipboard-write'],{origin:base});
        await page.evaluate(async ()=>{
          await navigator.clipboard.writeText('isolated-browser-password');
        });
        await page.keyboard.press('Control+V');
      }
      assert.equal(await ownerPassword.inputValue(),'isolated-browser-password');
      await consent.check();
      assert.equal(await consent.isChecked(),true);
      assert.equal(await form.getAttribute('data-admin-dirty'),null,
        'Owner acknowledgement is not an unsaved persisted form change');
      // Later silent password-manager replacement invalidates the exact
      // approved value even if the browser emits no events.
      await ownerPassword.evaluate(control=>{control.value='passive-late-replacement';});
      await button.click();
      assert.equal(submitted,0,kind+' late passive overwrite replaced approved value');
      assert.equal(await consent.isChecked(),false);
      // A browser input/change after approval also revokes consent, even
      // when the event looks native and the eventual value is unchanged.
      await ownerPassword.fill('isolated-browser-password');
      await consent.check();
      await ownerPassword.fill('isolated-browser-password');
      await button.click();
      assert.equal(submitted,0,kind+' later browser input failed to revoke approval');

      await ownerPassword.fill('isolated-browser-password');
      await consent.focus();
      await page.keyboard.press('Space'); // keyboard approval, followed by a real POST
      assert.equal(await consent.isChecked(),true);
      const sent=page.waitForResponse(response=>response.request().method()==='POST'
        && new URL(response.url()).pathname===endpoint);
      await button.click();
      assert.equal((await sent).status(),302);
      assert.equal(submitted,1);
      page.off('request',track);
      await page.goto(url);
      assert.equal(await page.getByRole('button',{name:label,exact:true}).count(),0);
    }
    pass('both real Owner grant-revocation forms reject autofill-only and permit confirmed actions');

    // Persist only a disabled Gateway configuration on the disposable fixture.
    // No SSHD/systemd or public endpoint is contacted.
    const algorithm=Buffer.from('ssh-ed25519');
    const hostKey=Buffer.concat([
      Buffer.from([0,0,0,algorithm.length]),algorithm,
      Buffer.from([0,0,0,32]),Buffer.alloc(32,33),
    ]);
    await page.goto(base+'/admin/settings/reverse-ssh');
    assert.ok(await page.getByRole('heading',{name:'One-time Gateway host setup'}).count()>0);
    assert.equal(await page.locator('ol.reverse-setup-list > li').count(),5);
    const diagnostics=page.locator('section[aria-labelledby="reverse-status"] details');
    assert.equal(await diagnostics.isVisible(),true);
    assert.equal(await diagnostics.evaluate(el=>el.open),false);
    for (const width of [360,390,768]) {
      await page.setViewportSize({width,height:950});
      for (const dir of ['ltr','rtl']) {
        await page.evaluate(dir=>document.documentElement.dir=dir,dir);
        const overflow=await page.evaluate(()=>document.documentElement.scrollWidth-document.documentElement.clientWidth);
        assert.ok(overflow<=1,'Reverse bootstrap must fit viewport: '+JSON.stringify({width,dir,overflow}));
      }
    }
    pass('pre-setup checklist and collapsed diagnostics fit mobile/RTL');
    await page.setViewportSize({width:1440,height:950});
    await page.evaluate(()=>document.documentElement.dir='ltr');
    if (await page.locator('#reverse_control_host').count() === 0) {
      await page.getByRole('link',{name:'Edit settings'}).click();
      await page.locator('#reverse_control_host').waitFor();
    }
    await page.locator('#reverse_control_host').fill('gateway.example.test');
    await page.locator('#reverse_control_port').fill('7770');
    await page.locator('#reverse_control_user').fill('mcp-reverse');
    await page.locator('#reverse_host_key').fill('ssh-ed25519 '+hostKey.toString('base64'));
    await page.locator('#reverse_owner_password').fill('isolated-browser-password');
    await page.locator('[data-admin-owner-approval-input]').first().check();
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
    await plain.goto(base+'/admin/targets/create');
    assert.equal(await plain.locator('[data-target-ssh-shortcut="managed"]').isVisible(),true);
    await plain.locator('[data-target-ssh-shortcut="managed"]').click();
    assert.equal(new URL(plain.url()).searchParams.get('ssh_mode'),'managed');
    let res=await plain.goto(base+'/admin/targets/create?connector_type=ssh_direct&ssh_mode=managed');
    assert.equal(res.status(),200);
    assert.ok(await plain.locator('noscript a[href*="ssh_mode=manual"]').count()>0);
    assert.equal(await plain.locator('#ssh_mode').isDisabled(),true,'No-JS mode is changed only by server links');
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
