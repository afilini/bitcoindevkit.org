(window.webpackJsonp=window.webpackJsonp||[]).push([[2],{1:function(e,n,t){"use strict";t.r(n);var i=t(2),o=t(4),r=t.n(o),a={backupBlocks_:function(e){if("localStorage"in window){var n=r.a.Xml.workspaceToDom(e),t=window.location.href.split("#")[0];window.localStorage.setItem(t,r.a.Xml.domToText(n))}},backupOnUnload:function(e){var n=e||r.a.getMainWorkspace();window.addEventListener("unload",(function(){a.backupBlocks_(n)}),!1)},restoreBlocks:function(e){var n=window.location.href.split("#")[0];if("localStorage"in window&&window.localStorage[n]){var t=e||r.a.getMainWorkspace(),i=r.a.Xml.textToDom(window.localStorage[n]);r.a.Xml.domToWorkspace(i,t)}},link:function(e){var n=e||r.a.getMainWorkspace(),t=r.a.Xml.workspaceToDom(n,!0);if(1==n.getTopBlocks(!1).length&&t.querySelector){var i=t.querySelector("block");i&&(i.removeAttribute("x"),i.removeAttribute("y"))}var o=r.a.Xml.domToText(t);a.makeRequest_("/storage","xml",o,n)},retrieveXml:function(e,n){var t=n||r.a.getMainWorkspace();a.makeRequest_("/storage","key",e,t)},httpRequest_:null,makeRequest_:function(e,n,t,i){a.httpRequest_&&a.httpRequest_.abort(),a.httpRequest_=new XMLHttpRequest,a.httpRequest_.name=n,a.httpRequest_.onreadystatechange=a.handleRequest_,a.httpRequest_.open("POST",e),a.httpRequest_.setRequestHeader("Content-Type","application/x-www-form-urlencoded"),a.httpRequest_.send(n+"="+encodeURIComponent(t)),a.httpRequest_.workspace=i},handleRequest_:function(){if(4==a.httpRequest_.readyState){if(200!=a.httpRequest_.status)a.alert(a.HTTPREQUEST_ERROR+"\nhttpRequest_.status: "+a.httpRequest_.status);else{var e=a.httpRequest_.responseText.trim();"xml"==a.httpRequest_.name?(window.location.hash=e,a.alert(a.LINK_ALERT.replace("%1",window.location.href))):"key"==a.httpRequest_.name&&(e.length?a.loadXml_(e,a.httpRequest_.workspace):a.alert(a.HASH_ERROR.replace("%1",window.location.hash))),a.monitorChanges_(a.httpRequest_.workspace)}a.httpRequest_=null}},monitorChanges_:function(e){var n=r.a.Xml.workspaceToDom(e),t=r.a.Xml.domToText(n);e.addChangeListener((function n(){var i=r.a.Xml.workspaceToDom(e),o=r.a.Xml.domToText(i);t!=o&&(window.location.hash="",e.removeChangeListener(n))}))},loadXml_:function(e,n){try{e=r.a.Xml.textToDom(e)}catch(n){return void a.alert(a.XML_ERROR+"\nXML: "+e)}n.clear(),r.a.Xml.domToWorkspace(e,n)},alert:function(e){window.alert(e)}},l=a;!async function(){Object(i.ob)(),function(e,n){console.log("Blockly starting");const t=document.getElementById(n);r.a.JavaScript.INDENT="";var i={toolbox:'<xml xmlns="https://developers.google.com/blockly/xml">\n  <category name="Miniscript" colour="#5ba55b">\n    <block type="and"></block>\n    <block type="or">\n      <field name="A_weight">1</field>\n      <field name="B_weight">1</field>\n    </block>\n    <block type="thresh">\n      <field name="Threshold">1</field>\n    </block>\n    <block type="after">\n      <field name="NAME">1</field>\n    </block>\n    <block type="pk"></block>\n    <block type="adapter"></block>\n    <block type="older">\n      <field name="NAME">1</field>\n    </block>\n    <block type="alias_key">\n      <field name="label">Alias</field>\n      <field name="name">name</field>\n    </block>\n    <block type="existing_key">\n      <field name="NAME">Existing Key</field>\n      <field name="key">tpub, WIF, hex...</field>\n    </block>\n  </category>\n  <category name="Examples" colour="#5b67a5">\n    <block type="pk">\n      <value name="pk">\n        <block type="alias_key">\n          <field name="label">Alias</field>\n          <field name="name">Alice</field>\n        </block>\n      </value>\n    </block>\n    <block type="or">\n      <field name="A_weight">1</field>\n      <field name="B_weight">1</field>\n      <statement name="A">\n        <block type="pk">\n          <value name="pk">\n            <block type="alias_key">\n              <field name="label">Alias</field>\n              <field name="name">Alice</field>\n            </block>\n          </value>\n        </block>\n      </statement>\n      <statement name="B">\n        <block type="pk">\n          <value name="pk">\n            <block type="alias_key">\n              <field name="label">Alias</field>\n              <field name="name">Bob</field>\n            </block>\n          </value>\n        </block>\n      </statement>\n    </block>\n    <block type="or">\n      <field name="A_weight">99</field>\n      <field name="B_weight">1</field>\n      <statement name="A">\n        <block type="pk">\n          <value name="pk">\n            <block type="alias_key">\n              <field name="label">Alias</field>\n              <field name="name">KeyLikely</field>\n            </block>\n          </value>\n        </block>\n      </statement>\n      <statement name="B">\n        <block type="pk">\n          <value name="pk">\n            <block type="alias_key">\n              <field name="label">Alias</field>\n              <field name="name">Likely</field>\n            </block>\n          </value>\n        </block>\n      </statement>\n    </block>\n    <block type="and">\n      <statement name="A">\n        <block type="pk">\n          <value name="pk">\n            <block type="alias_key">\n              <field name="label">Alias</field>\n              <field name="name">User</field>\n            </block>\n          </value>\n        </block>\n      </statement>\n      <statement name="B">\n        <block type="or">\n          <field name="A_weight">99</field>\n          <field name="B_weight">1</field>\n          <statement name="A">\n            <block type="pk">\n              <value name="pk">\n                <block type="alias_key">\n                  <field name="label">Alias</field>\n                  <field name="name">Service</field>\n                </block>\n              </value>\n            </block>\n          </statement>\n          <statement name="B">\n            <block type="older">\n              <field name="NAME">12960</field>\n            </block>\n          </statement>\n        </block>\n      </statement>\n    </block>\n    <block type="thresh">\n      <field name="Threshold">3</field>\n      <statement name="A">\n        <block type="adapter">\n          <statement name="NAME">\n            <block type="pk">\n              <value name="pk">\n                <block type="alias_key">\n                  <field name="label">Alias</field>\n                  <field name="name">Alice</field>\n                </block>\n              </value>\n            </block>\n          </statement>\n          <next>\n            <block type="adapter">\n              <statement name="NAME">\n                <block type="pk">\n                  <value name="pk">\n                    <block type="alias_key">\n                      <field name="label">Alias</field>\n                      <field name="name">Bob</field>\n                    </block>\n                  </value>\n                </block>\n              </statement>\n              <next>\n                <block type="adapter">\n                  <statement name="NAME">\n                    <block type="pk">\n                      <value name="pk">\n                        <block type="alias_key">\n                          <field name="label">Alias</field>\n                          <field name="name">Carol</field>\n                        </block>\n                      </value>\n                    </block>\n                  </statement>\n                  <next>\n                    <block type="adapter">\n                      <statement name="NAME">\n                        <block type="older">\n                          <field name="NAME">12960</field>\n                        </block>\n                      </statement>\n                    </block>\n                  </next>\n                </block>\n              </next>\n            </block>\n          </next>\n        </block>\n      </statement>\n    </block>\n  </category>\n</xml>',collapse:!0,comments:!0,disable:!0,maxBlocks:1/0,trashcan:!0,horizontalLayout:!0,toolboxPosition:"start",css:!0,media:"https://blockly-demo.appspot.com/static/media/",rtl:!1,scrollbars:!0,sounds:!0,oneBasedIndex:!0,grid:{spacing:20,length:1,colour:"#888",snap:!0}};r.a.Blocks.pk={init:function(){this.appendValueInput("pk").setCheck("key").appendField("Key"),this.setPreviousStatement(!0,"policy"),this.setColour(260),this.setTooltip("Requires a signature with a given public key"),this.setHelpUrl("")}},r.a.Blocks.begin={init:function(){this.appendDummyInput().appendField("Begin"),this.setNextStatement(!0,"policy"),this.setColour(160),this.setTooltip("Sets the beginning of the policy"),this.setHelpUrl("")}},r.a.Blocks.existing_key={init:function(){this.appendDummyInput().appendField(new r.a.FieldLabelSerializable("Existing Key"),"NAME").appendField(new r.a.FieldTextInput("tpub, WIF, hex..."),"key"),this.setOutput(!0,"key"),this.setColour(120),this.setTooltip("Sets the value of a key to an existing WIF key, xpub or hex public key"),this.setHelpUrl("")}},r.a.Blocks.alias_key={init:function(){this.appendDummyInput().appendField(new r.a.FieldLabelSerializable("Alias"),"label").appendField(new r.a.FieldTextInput("name"),"name"),this.setOutput(!0,"key"),this.setColour(120),this.setTooltip("Sets the value of a key to an alias"),this.setHelpUrl("")}},r.a.Blocks.thresh={init:function(){this.appendDummyInput().appendField("Threshold").appendField(new r.a.FieldNumber(1,1,1/0,1),"Threshold"),this.appendStatementInput("A").setCheck("thresh").appendField("Policies"),this.setPreviousStatement(!0,"policy"),this.setColour(230),this.setTooltip("Creates a threshold element (m-of-n), where the 'm' field is manually set and 'n' is implied by the number of sub-policies added. Requies all of its children to be wrapped in the 'Entry' block"),this.setHelpUrl("")}},r.a.Blocks.older={init:function(){this.appendDummyInput().appendField("Older").appendField(new r.a.FieldNumber(1,1,1/0,1),"NAME"),this.setPreviousStatement(!0,"policy"),this.setColour(20),this.setTooltip("Requires waiting a number of blocks from the confirmation height of a UTXO before it becomes spendable"),this.setHelpUrl("")}},r.a.Blocks.after={init:function(){this.appendDummyInput().appendField("After").appendField(new r.a.FieldNumber(1,1,1/0,1),"NAME"),this.setPreviousStatement(!0,"policy"),this.setColour(20),this.setTooltip("Requires the blockchain to reach a specific block height before the UTXO becomes spendable"),this.setHelpUrl("")}},r.a.Blocks.adapter={init:function(){this.appendStatementInput("NAME").setCheck("policy").appendField("Entry"),this.setPreviousStatement(!0,"thresh"),this.setNextStatement(!0,"thresh"),this.setColour(290),this.setTooltip("Adapter used to stack policies into 'Threshold' blocks"),this.setHelpUrl("")}},r.a.Blocks.and={init:function(){this.appendStatementInput("A").setCheck("policy"),this.appendDummyInput().appendField("AND"),this.appendStatementInput("B").setCheck("policy"),this.setPreviousStatement(!0,"policy"),this.setColour(230),this.setTooltip("Requires both sub-policies to be satisfied"),this.setHelpUrl("")}},r.a.Blocks.or={init:function(){this.appendStatementInput("A").setCheck("policy").appendField("Weight").appendField(new r.a.FieldNumber(1,1),"A_weight"),this.appendDummyInput().appendField("OR"),this.appendStatementInput("B").setCheck("policy").appendField("Weight").appendField(new r.a.FieldNumber(1,1),"B_weight"),this.setPreviousStatement(!0,"policy"),this.setColour(230),this.setTooltip("Requires either one of the two sub-policies to be satisfied. Weights can be used to indicate the relative probability of each sub-policy"),this.setHelpUrl("")}},r.a.JavaScript.begin=function(e){return""},r.a.JavaScript.pk=function(e){if(!e.getParent())return"";var n=r.a.JavaScript.valueToCode(e,"pk",r.a.JavaScript.ORDER_ATOMIC);return""==n&&(n="()"),"pk"+n},r.a.JavaScript.existing_key=function(e){return e.getParent()?[e.getFieldValue("key"),r.a.JavaScript.ORDER_NONE]:["",r.a.JavaScript.ORDER_NONE]},r.a.JavaScript.alias_key=function(e){return e.getParent()?[e.getFieldValue("name"),r.a.JavaScript.ORDER_NONE]:["",r.a.JavaScript.ORDER_NONE]},r.a.JavaScript.thresh=function(e){return"thresh("+e.getFieldValue("Threshold")+","+r.a.JavaScript.statementToCode(e,"A")+")"},r.a.JavaScript.older=function(e){return e.getParent()?"older("+e.getFieldValue("NAME")+")":""},r.a.JavaScript.after=function(e){return e.getParent()?"after("+e.getFieldValue("NAME")+")":""},r.a.JavaScript.adapter=function(e){return e.getParent()?r.a.JavaScript.statementToCode(e,"NAME")+(e.getNextBlock()?",":""):""},r.a.JavaScript.and=function(e){return e.getParent()?"and("+r.a.JavaScript.statementToCode(e,"A")+","+r.a.JavaScript.statementToCode(e,"B")+")":""},r.a.JavaScript.or=function(e){if(!e.getParent())return"";var n=e.getFieldValue("A_weight");"1"==n?n="":n+="@";var t=r.a.JavaScript.statementToCode(e,"A"),i=e.getFieldValue("B_weight");return"1"==i?i="":i+="@","or("+n+t+","+i+r.a.JavaScript.statementToCode(e,"B")+")"};var o=r.a.inject(e,i);o.addChangeListener((function(e){t.value=r.a.JavaScript.workspaceToCode(o)})),o.addChangeListener(r.a.Events.disableOrphans),setTimeout(()=>{if(l.restoreBlocks(),0==o.getTopBlocks().length){var e=o.newBlock("begin");e.setDeletable(!1),e.setEditable(!1),e.moveBy(20,20),e.initSvg(),e.render()}const n=document.createElement("span");n.innerHTML='<i class="fas fa-expand"></i>',n.style.float="right",n.style["margin-right"]="10px";let t=!1;n.onclick=function(){t?document.exitFullscreen():document.getElementById("blocklyDiv").requestFullscreen(),t=!t},document.getElementsByClassName("blocklyToolboxDiv")[0].appendChild(n)},0),l.backupOnUnload()}("blocklyDiv","policy");let e=null;document.getElementById("stdin").disabled=!0;const n=document.getElementById("start_button"),t=document.getElementById("stop_button"),o=document.getElementById("start_message");n.disabled=!1,t.disabled=!0;const a=document.getElementById("descriptor"),u=document.getElementById("change_descriptor");n.onclick=r=>{0!=a.value.length&&(r.preventDefault(),async function(e,n){const t=document.getElementById("stdout"),o=document.getElementById("stdin");o.disabled=!1;const r=[];let a=0;const l=await new i.a("testnet",e,n,"https://blockstream.info/testnet/api"),u=e=>{if("clear"!=e)return o.disabled=!0,t.innerHTML.length>0&&(t.innerHTML+="\n"),t.innerHTML+=`<span class="command">> ${e}</span>\n`,a=r.push(e),l.run(e).then(e=>{e&&(t.innerHTML+=`<span class="success">${e}</span>\n`)}).catch(e=>t.innerHTML+=`<span class="error">${e}</span>\n`).finally(()=>{o.disabled=!1,t.scrollTop=t.scrollHeight-t.clientHeight});t.innerHTML=""};return o.onkeydown=e=>{if("Enter"==e.key){if(0==o.value.length)return;u(o.value),o.value="",e.preventDefault()}else"ArrowUp"==e.key?a>0&&(o.value=r[--a]):"ArrowDown"==e.key&&a<r.length&&(o.value=r[++a]||"")},{run:u}}(a.value,u.value.length>0?u.value:null).then(i=>{n.disabled=!0,a.disabled=!0,u.disabled=!0,o.innerHTML="Wallet created, running `sync`...",i.run("sync").then(()=>o.innerHTML="Ready!"),e=i,t.disabled=!1}).catch(e=>o.innerHTML=`<span class="error">${e}</span>`))},t.onclick=i=>{null!=e&&(i.preventDefault(),e.free(),o.innerHTML="Wallet instance destroyed",n.disabled=!1,t.disabled=!0,a.disabled=!1,u.disabled=!1)};const c=document.getElementById("policy"),s=document.getElementById("compiler_script_type"),d=document.getElementById("compiler_output");document.getElementById("compile_button").onclick=e=>{if(0==c.value.length)return;e.preventDefault();const n=!e.target.form.elements.namedItem("alias").length;let t=e.target.form.elements.namedItem("alias"),o=e.target.form.elements.namedItem("type"),r=e.target.form.elements.namedItem("extra");n?(t=[t],o=[o],r=[r]):(t=Array.from(t),o=Array.from(o),r=Array.from(r));const a={};t.forEach(e=>{const n=o.filter(n=>n.attributes["data-index"].value==e.attributes["data-index"].value)[0].value,t=r.filter(n=>n.attributes["data-index"].value==e.attributes["data-index"].value)[0].value,i=e.value;a[i]={type:n,extra:t}}),Object(i.nb)(c.value,JSON.stringify(a),s.value).then(e=>d.innerHTML=e).catch(e=>d.innerHTML=`<span class="error">${e}</span>`)}}()},12:function(e,n,t){"use strict";var i=t.w[e.i];e.exports=i;t(2);i.n()},2:function(e,n,t){"use strict";(function(e){t.d(n,"ob",(function(){return w})),t.d(n,"nb",(function(){return _})),t.d(n,"a",(function(){return S})),t.d(n,"jb",(function(){return E})),t.d(n,"Y",(function(){return R})),t.d(n,"lb",(function(){return x})),t.d(n,"A",(function(){return B})),t.d(n,"Q",(function(){return I})),t.d(n,"l",(function(){return F})),t.d(n,"gb",(function(){return q})),t.d(n,"N",(function(){return C})),t.d(n,"L",(function(){return N})),t.d(n,"i",(function(){return M})),t.d(n,"x",(function(){return D})),t.d(n,"fb",(function(){return O})),t.d(n,"o",(function(){return H})),t.d(n,"p",(function(){return J})),t.d(n,"K",(function(){return L})),t.d(n,"R",(function(){return P})),t.d(n,"n",(function(){return U})),t.d(n,"ib",(function(){return X})),t.d(n,"j",(function(){return j})),t.d(n,"m",(function(){return W})),t.d(n,"s",(function(){return V})),t.d(n,"w",(function(){return $})),t.d(n,"Z",(function(){return K})),t.d(n,"G",(function(){return z})),t.d(n,"t",(function(){return Q})),t.d(n,"W",(function(){return G})),t.d(n,"S",(function(){return Y})),t.d(n,"r",(function(){return Z})),t.d(n,"e",(function(){return ee})),t.d(n,"T",(function(){return ne})),t.d(n,"F",(function(){return te})),t.d(n,"z",(function(){return ie})),t.d(n,"d",(function(){return oe})),t.d(n,"c",(function(){return re})),t.d(n,"B",(function(){return ae})),t.d(n,"b",(function(){return le})),t.d(n,"ab",(function(){return ue})),t.d(n,"db",(function(){return ce})),t.d(n,"eb",(function(){return se})),t.d(n,"I",(function(){return de})),t.d(n,"k",(function(){return fe})),t.d(n,"X",(function(){return pe})),t.d(n,"u",(function(){return me})),t.d(n,"g",(function(){return be})),t.d(n,"h",(function(){return he})),t.d(n,"H",(function(){return ke})),t.d(n,"J",(function(){return ye})),t.d(n,"y",(function(){return ge})),t.d(n,"D",(function(){return ve})),t.d(n,"M",(function(){return we})),t.d(n,"V",(function(){return _e})),t.d(n,"U",(function(){return Te})),t.d(n,"f",(function(){return Ae})),t.d(n,"E",(function(){return Se})),t.d(n,"C",(function(){return Ee})),t.d(n,"P",(function(){return Re})),t.d(n,"v",(function(){return xe})),t.d(n,"q",(function(){return Be})),t.d(n,"O",(function(){return Ie})),t.d(n,"kb",(function(){return Fe})),t.d(n,"cb",(function(){return qe})),t.d(n,"mb",(function(){return Ce})),t.d(n,"hb",(function(){return Ne})),t.d(n,"bb",(function(){return Me}));var i=t(12);const o=new Array(32).fill(void 0);function r(e){return o[e]}o.push(void 0,null,!0,!1);let a=o.length;function l(e){const n=r(e);return function(e){e<36||(o[e]=a,a=e)}(e),n}let u=new("undefined"==typeof TextDecoder?(0,e.require)("util").TextDecoder:TextDecoder)("utf-8",{ignoreBOM:!0,fatal:!0});u.decode();let c=null;function s(){return null!==c&&c.buffer===i.j.buffer||(c=new Uint8Array(i.j.buffer)),c}function d(e,n){return u.decode(s().subarray(e,e+n))}function f(e){a===o.length&&o.push(o.length+1);const n=a;return a=o[n],o[n]=e,n}let p=0;let m=new("undefined"==typeof TextEncoder?(0,e.require)("util").TextEncoder:TextEncoder)("utf-8");const b="function"==typeof m.encodeInto?function(e,n){return m.encodeInto(e,n)}:function(e,n){const t=m.encode(e);return n.set(t),{read:e.length,written:t.length}};function h(e,n,t){if(void 0===t){const t=m.encode(e),i=n(t.length);return s().subarray(i,i+t.length).set(t),p=t.length,i}let i=e.length,o=n(i);const r=s();let a=0;for(;a<i;a++){const n=e.charCodeAt(a);if(n>127)break;r[o+a]=n}if(a!==i){0!==a&&(e=e.slice(a)),o=t(o,i,i=a+3*e.length);const n=s().subarray(o+a,o+i);a+=b(e,n).written}return p=a,o}let k=null;function y(){return null!==k&&k.buffer===i.j.buffer||(k=new Int32Array(i.j.buffer)),k}function g(e){return null==e}function v(e,n,t){i.g(e,n,f(t))}function w(){i.i()}function _(e,n,t){var o=h(e,i.e,i.f),r=p,a=h(n,i.e,i.f),u=p,c=h(t,i.e,i.f),s=p;return l(i.h(o,r,a,u,c,s))}function T(e){return function(){try{return e.apply(this,arguments)}catch(e){i.b(f(e))}}}function A(e,n){return s().subarray(e/1,e/1+n)}class S{static __wrap(e){const n=Object.create(S.prototype);return n.ptr=e,n}free(){const e=this.ptr;this.ptr=0,i.a(e)}constructor(e,n,t,o){var r=h(e,i.e,i.f),a=p,u=h(n,i.e,i.f),c=p,s=g(t)?0:h(t,i.e,i.f),d=p,f=h(o,i.e,i.f),m=p;return l(i.k(r,a,u,c,s,d,f,m))}run(e){var n=h(e,i.e,i.f),t=p;return l(i.l(this.ptr,n,t))}}const E=function(e){l(e)},R=function(e){return f(S.__wrap(e))},x=function(e,n){return f(d(e,n))},B=function(){return f(new Error)},I=function(e,n){var t=h(r(n).stack,i.e,i.f),o=p;y()[e/4+1]=o,y()[e/4+0]=t},F=function(e,n){try{console.error(d(e,n))}finally{i.d(e,n)}},q=function(e,n){const t=r(n);var o=h(JSON.stringify(void 0===t?null:t),i.e,i.f),a=p;y()[e/4+1]=a,y()[e/4+0]=o},C=T((function(){return f(self.self)})),N=function(e,n,t){return f(r(e).require(d(n,t)))},M=function(e){return f(r(e).crypto)},D=function(e){return f(r(e).msCrypto)},O=function(e){return void 0===r(e)},H=function(e){return f(r(e).getRandomValues)},J=function(e,n,t){r(e).getRandomValues(A(n,t))},L=function(e,n,t){r(e).randomFillSync(A(n,t))},P=function(){return f(e)},U=function(e){return f(fetch(r(e)))},X=function(e){return f(r(e))},j=function(e){console.debug(r(e))},W=function(e){console.error(r(e))},V=function(e){console.info(r(e))},$=function(e){console.log(r(e))},K=function(e){console.warn(r(e))},z=T((function(e,n){return f(new Blob(r(e),r(n)))})),Q=function(e){return r(e)instanceof Response},G=function(e,n){var t=h(r(n).url,i.e,i.f),o=p;y()[e/4+1]=o,y()[e/4+0]=t},Y=function(e){return r(e).status},Z=function(e){return f(r(e).headers)},ee=T((function(e){return f(r(e).arrayBuffer())})),ne=T((function(e){return f(r(e).text())})),te=T((function(e,n,t){return f(new Request(d(e,n),r(t)))})),ie=T((function(){return f(new FormData)})),oe=T((function(e,n,t,i){r(e).append(d(n,t),r(i))})),re=T((function(e,n,t,i,o,a){r(e).append(d(n,t),r(i),d(o,a))})),ae=T((function(){return f(new Headers)})),le=T((function(e,n,t,i,o){r(e).append(d(n,t),d(i,o))})),ue=function(e){const n=l(e).original;if(1==n.cnt--)return n.a=0,!0;return!1},ce=function(e){return"function"==typeof r(e)},se=function(e){const n=r(e);return"object"==typeof n&&null!==n},de=function(e){return f(r(e).next)},fe=function(e){return r(e).done},pe=function(e){return f(r(e).value)},me=function(){return f(Symbol.iterator)},be=T((function(e,n){return f(r(e).call(r(n)))})),he=T((function(e,n,t){return f(r(e).call(r(n),r(t)))})),ke=T((function(e){return f(r(e).next())})),ye=function(){return Date.now()},ge=function(){return f(new Object)},ve=function(e,n){try{var t={a:e,b:n},o=new Promise((e,n)=>{const o=t.a;t.a=0;try{return function(e,n,t,o){i.m(e,n,f(t),f(o))}(o,t.b,e,n)}finally{t.a=o}});return f(o)}finally{t.a=t.b=0}},we=function(e){return f(Promise.resolve(r(e)))},_e=function(e,n){return f(r(e).then(r(n)))},Te=function(e,n,t){return f(r(e).then(r(n),r(t)))},Ae=function(e){return f(r(e).buffer)},Se=function(e,n,t){return f(new Uint8Array(r(e),n>>>0,t>>>0))},Ee=function(e){return f(new Uint8Array(r(e)))},Re=function(e,n,t){r(e).set(r(n),t>>>0)},xe=function(e){return r(e).length},Be=T((function(e,n){return f(Reflect.get(r(e),r(n)))})),Ie=T((function(e,n,t){return Reflect.set(r(e),r(n),r(t))})),Fe=function(e,n){const t=r(n);var o="string"==typeof t?t:void 0,a=g(o)?0:h(o,i.e,i.f),l=p;y()[e/4+1]=l,y()[e/4+0]=a},qe=function(e,n){var t=h(function e(n){const t=typeof n;if("number"==t||"boolean"==t||null==n)return""+n;if("string"==t)return`"${n}"`;if("symbol"==t){const e=n.description;return null==e?"Symbol":`Symbol(${e})`}if("function"==t){const e=n.name;return"string"==typeof e&&e.length>0?`Function(${e})`:"Function"}if(Array.isArray(n)){const t=n.length;let i="[";t>0&&(i+=e(n[0]));for(let o=1;o<t;o++)i+=", "+e(n[o]);return i+="]",i}const i=/\[object ([^\]]+)\]/.exec(toString.call(n));let o;if(!(i.length>1))return toString.call(n);if(o=i[1],"Object"==o)try{return"Object("+JSON.stringify(n)+")"}catch(e){return"Object"}return n instanceof Error?`${n.name}: ${n.message}\n${n.stack}`:o}(r(n)),i.e,i.f),o=p;y()[e/4+1]=o,y()[e/4+0]=t},Ce=function(e,n){throw new Error(d(e,n))},Ne=function(){return f(i.j)},Me=function(e,n,t){return f(function(e,n,t,o){const r={a:e,b:n,cnt:1,dtor:t},a=(...e)=>{r.cnt++;const n=r.a;r.a=0;try{return o(n,r.b,...e)}finally{0==--r.cnt?i.c.get(r.dtor)(n,r.b):r.a=n}};return a.original=r,a}(e,n,1080,v))}}).call(this,t(11)(e))}}]);