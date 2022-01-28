(window.webpackJsonp=window.webpackJsonp||[]).push([[27],{447:function(t,s,e){"use strict";e.r(s);var a=e(18),n=Object(a.a)({},(function(){var t=this,s=t.$createElement,e=t._self._c||s;return e("ContentSlotsDistributor",{attrs:{"slot-key":t.$parent.slotKey}},[e("p",[t._v("A new release of BDK is out: the "),e("a",{attrs:{href:"https://crates.io/crates/bdk/0.3.0",target:"_blank",rel:"noopener noreferrer"}},[e("code",[t._v("v0.3.0")]),e("OutboundLink")],1),t._v(" is a relatively small update compared to "),e("code",[t._v("v0.2.0")]),t._v(", but it still brings some nice APIs improvements and general bugfixes.")]),t._v(" "),e("p",[t._v("You can find the full "),e("a",{attrs:{href:"https://github.com/bitcoindevkit/bdk/blob/75669049268bbc294564f8c6e0528e07a546258f/CHANGELOG.md#v030---v020",target:"_blank",rel:"noopener noreferrer"}},[t._v("v0.3.0 changelog"),e("OutboundLink")],1),t._v(" on GitHub.")]),t._v(" "),e("h2",{attrs:{id:"whats-new-in-v030"}},[e("a",{staticClass:"header-anchor",attrs:{href:"#whats-new-in-v030"}},[t._v("#")]),t._v(" What's new in v0.3.0")]),t._v(" "),e("p",[t._v("Below are some highlights of the new improved APIs coming with this release:")]),t._v(" "),e("h3",{attrs:{id:"less-verbosity-when-using-walletnew-offline"}},[e("a",{staticClass:"header-anchor",attrs:{href:"#less-verbosity-when-using-walletnew-offline"}},[t._v("#")]),t._v(" Less verbosity when using "),e("code",[t._v("Wallet::new_offline()")])]),t._v(" "),e("p",[t._v("Now you don't have to explicitly provide the "),e("code",[t._v("OfflineWallet<_>")]),t._v(" type anymore, saving you one import and making it much less verbose to use.")]),t._v(" "),e("p",[t._v("Where before you were doing:")]),t._v(" "),e("div",{staticClass:"language-rust extra-class"},[e("pre",{pre:!0,attrs:{class:"language-rust"}},[e("code",[e("span",{pre:!0,attrs:{class:"token keyword"}},[t._v("let")]),t._v(" wallet"),e("span",{pre:!0,attrs:{class:"token punctuation"}},[t._v(":")]),t._v(" "),e("span",{pre:!0,attrs:{class:"token class-name"}},[t._v("OfflineWallet")]),e("span",{pre:!0,attrs:{class:"token operator"}},[t._v("<")]),t._v("_"),e("span",{pre:!0,attrs:{class:"token operator"}},[t._v(">")]),t._v(" "),e("span",{pre:!0,attrs:{class:"token operator"}},[t._v("=")]),t._v(" "),e("span",{pre:!0,attrs:{class:"token class-name"}},[t._v("Wallet")]),e("span",{pre:!0,attrs:{class:"token punctuation"}},[t._v("::")]),e("span",{pre:!0,attrs:{class:"token function"}},[t._v("new_offline")]),e("span",{pre:!0,attrs:{class:"token punctuation"}},[t._v("(")]),e("span",{pre:!0,attrs:{class:"token punctuation"}},[t._v("...")]),e("span",{pre:!0,attrs:{class:"token punctuation"}},[t._v(")")]),e("span",{pre:!0,attrs:{class:"token operator"}},[t._v("?")]),e("span",{pre:!0,attrs:{class:"token punctuation"}},[t._v(";")]),t._v("\n")])])]),e("p",[t._v("Now you can just write:")]),t._v(" "),e("div",{staticClass:"language-rust extra-class"},[e("pre",{pre:!0,attrs:{class:"language-rust"}},[e("code",[e("span",{pre:!0,attrs:{class:"token keyword"}},[t._v("let")]),t._v(" wallet "),e("span",{pre:!0,attrs:{class:"token operator"}},[t._v("=")]),t._v(" "),e("span",{pre:!0,attrs:{class:"token class-name"}},[t._v("Wallet")]),e("span",{pre:!0,attrs:{class:"token punctuation"}},[t._v("::")]),e("span",{pre:!0,attrs:{class:"token function"}},[t._v("new_offline")]),e("span",{pre:!0,attrs:{class:"token punctuation"}},[t._v("(")]),e("span",{pre:!0,attrs:{class:"token punctuation"}},[t._v("...")]),e("span",{pre:!0,attrs:{class:"token punctuation"}},[t._v(")")]),e("span",{pre:!0,attrs:{class:"token operator"}},[t._v("?")]),e("span",{pre:!0,attrs:{class:"token punctuation"}},[t._v(";")]),t._v("\n")])])]),e("h3",{attrs:{id:"no-more-error-conversions-in-descriptortemplate"}},[e("a",{staticClass:"header-anchor",attrs:{href:"#no-more-error-conversions-in-descriptortemplate"}},[t._v("#")]),t._v(" No more error conversions in "),e("code",[t._v("DescriptorTemplate")])]),t._v(" "),e("p",[t._v("The "),e("code",[t._v("DescriptorTemplate")]),t._v(" trait has been updated to return a "),e("a",{attrs:{href:"https://docs.rs/bdk/0.3.0/bdk/descriptor/error/enum.Error.html",target:"_blank",rel:"noopener noreferrer"}},[e("code",[t._v("descriptor::error::Error")]),e("OutboundLink")],1),t._v(" instead of a "),e("code",[t._v("KeyError")]),t._v(". The "),e("a",{attrs:{href:"https://docs.rs/bdk/0.3.0/bdk/macro.descriptor.html",target:"_blank",rel:"noopener noreferrer"}},[e("code",[t._v("descriptor!()")]),e("OutboundLink")],1),t._v(" macro has been updated as well, which means that now you can use the macro inside a "),e("code",[t._v("DescriptorTemplate::build()")]),t._v(" implementation\nwithout having to "),e("RouterLink",{attrs:{to:"/blog/2020/12/release-v0.2.0/#descriptor-macro"}},[t._v("map the error")]),t._v(", like so:")],1),t._v(" "),e("div",{staticClass:"language-rust extra-class"},[e("pre",{pre:!0,attrs:{class:"language-rust"}},[e("code",[e("span",{pre:!0,attrs:{class:"token keyword"}},[t._v("pub")]),t._v(" "),e("span",{pre:!0,attrs:{class:"token keyword"}},[t._v("struct")]),t._v(" "),e("span",{pre:!0,attrs:{class:"token type-definition class-name"}},[t._v("TimeDecayingMultisig")]),e("span",{pre:!0,attrs:{class:"token operator"}},[t._v("<")]),e("span",{pre:!0,attrs:{class:"token class-name"}},[t._v("K")]),e("span",{pre:!0,attrs:{class:"token operator"}},[t._v(">")]),t._v(" "),e("span",{pre:!0,attrs:{class:"token punctuation"}},[t._v("{")]),t._v("\n    pk_a"),e("span",{pre:!0,attrs:{class:"token punctuation"}},[t._v(":")]),t._v(" "),e("span",{pre:!0,attrs:{class:"token class-name"}},[t._v("K")]),e("span",{pre:!0,attrs:{class:"token punctuation"}},[t._v(",")]),t._v("\n    pk_b"),e("span",{pre:!0,attrs:{class:"token punctuation"}},[t._v(":")]),t._v(" "),e("span",{pre:!0,attrs:{class:"token class-name"}},[t._v("K")]),e("span",{pre:!0,attrs:{class:"token punctuation"}},[t._v(",")]),t._v("\n    timelock"),e("span",{pre:!0,attrs:{class:"token punctuation"}},[t._v(":")]),t._v(" "),e("span",{pre:!0,attrs:{class:"token keyword"}},[t._v("u32")]),e("span",{pre:!0,attrs:{class:"token punctuation"}},[t._v(",")]),t._v("\n"),e("span",{pre:!0,attrs:{class:"token punctuation"}},[t._v("}")]),t._v("\n\n"),e("span",{pre:!0,attrs:{class:"token keyword"}},[t._v("impl")]),e("span",{pre:!0,attrs:{class:"token operator"}},[t._v("<")]),e("span",{pre:!0,attrs:{class:"token class-name"}},[t._v("K")]),e("span",{pre:!0,attrs:{class:"token punctuation"}},[t._v(":")]),t._v(" "),e("span",{pre:!0,attrs:{class:"token class-name"}},[t._v("ToDescriptorKey")]),e("span",{pre:!0,attrs:{class:"token operator"}},[t._v("<")]),e("span",{pre:!0,attrs:{class:"token class-name"}},[t._v("Segwitv0")]),e("span",{pre:!0,attrs:{class:"token operator"}},[t._v(">>")]),t._v(" "),e("span",{pre:!0,attrs:{class:"token class-name"}},[t._v("DescriptorTemplate")]),t._v(" "),e("span",{pre:!0,attrs:{class:"token keyword"}},[t._v("for")]),t._v(" "),e("span",{pre:!0,attrs:{class:"token class-name"}},[t._v("TimeDecayingMultisig")]),e("span",{pre:!0,attrs:{class:"token operator"}},[t._v("<")]),e("span",{pre:!0,attrs:{class:"token class-name"}},[t._v("K")]),e("span",{pre:!0,attrs:{class:"token operator"}},[t._v(">")]),t._v(" "),e("span",{pre:!0,attrs:{class:"token punctuation"}},[t._v("{")]),t._v("\n    "),e("span",{pre:!0,attrs:{class:"token keyword"}},[t._v("fn")]),t._v(" "),e("span",{pre:!0,attrs:{class:"token function-definition function"}},[t._v("build")]),e("span",{pre:!0,attrs:{class:"token punctuation"}},[t._v("(")]),e("span",{pre:!0,attrs:{class:"token keyword"}},[t._v("self")]),e("span",{pre:!0,attrs:{class:"token punctuation"}},[t._v(")")]),t._v(" "),e("span",{pre:!0,attrs:{class:"token punctuation"}},[t._v("->")]),t._v(" "),e("span",{pre:!0,attrs:{class:"token class-name"}},[t._v("Result")]),e("span",{pre:!0,attrs:{class:"token operator"}},[t._v("<")]),e("span",{pre:!0,attrs:{class:"token class-name"}},[t._v("DescriptorTemplateOut")]),e("span",{pre:!0,attrs:{class:"token punctuation"}},[t._v(",")]),t._v(" "),e("span",{pre:!0,attrs:{class:"token namespace"}},[t._v("descriptor"),e("span",{pre:!0,attrs:{class:"token punctuation"}},[t._v("::")]),t._v("error"),e("span",{pre:!0,attrs:{class:"token punctuation"}},[t._v("::")])]),e("span",{pre:!0,attrs:{class:"token class-name"}},[t._v("Error")]),e("span",{pre:!0,attrs:{class:"token operator"}},[t._v(">")]),t._v(" "),e("span",{pre:!0,attrs:{class:"token punctuation"}},[t._v("{")]),t._v("\n        "),e("span",{pre:!0,attrs:{class:"token namespace"}},[t._v("bdk"),e("span",{pre:!0,attrs:{class:"token punctuation"}},[t._v("::")])]),e("span",{pre:!0,attrs:{class:"token macro property"}},[t._v("descriptor!")]),e("span",{pre:!0,attrs:{class:"token punctuation"}},[t._v("(")]),e("span",{pre:!0,attrs:{class:"token function"}},[t._v("wsh")]),e("span",{pre:!0,attrs:{class:"token punctuation"}},[t._v("(")]),e("span",{pre:!0,attrs:{class:"token function"}},[t._v("thresh")]),e("span",{pre:!0,attrs:{class:"token punctuation"}},[t._v("(")]),e("span",{pre:!0,attrs:{class:"token number"}},[t._v("2")]),e("span",{pre:!0,attrs:{class:"token punctuation"}},[t._v(",")]),e("span",{pre:!0,attrs:{class:"token function"}},[t._v("pk")]),e("span",{pre:!0,attrs:{class:"token punctuation"}},[t._v("(")]),e("span",{pre:!0,attrs:{class:"token keyword"}},[t._v("self")]),e("span",{pre:!0,attrs:{class:"token punctuation"}},[t._v(".")]),t._v("pk_a"),e("span",{pre:!0,attrs:{class:"token punctuation"}},[t._v(")")]),e("span",{pre:!0,attrs:{class:"token punctuation"}},[t._v(",")]),t._v("s"),e("span",{pre:!0,attrs:{class:"token punctuation"}},[t._v(":")]),e("span",{pre:!0,attrs:{class:"token function"}},[t._v("pk")]),e("span",{pre:!0,attrs:{class:"token punctuation"}},[t._v("(")]),e("span",{pre:!0,attrs:{class:"token keyword"}},[t._v("self")]),e("span",{pre:!0,attrs:{class:"token punctuation"}},[t._v(".")]),t._v("pk_b"),e("span",{pre:!0,attrs:{class:"token punctuation"}},[t._v(")")]),e("span",{pre:!0,attrs:{class:"token punctuation"}},[t._v(",")]),t._v("s"),e("span",{pre:!0,attrs:{class:"token punctuation"}},[t._v(":")]),t._v("d"),e("span",{pre:!0,attrs:{class:"token punctuation"}},[t._v(":")]),t._v("v"),e("span",{pre:!0,attrs:{class:"token punctuation"}},[t._v(":")]),e("span",{pre:!0,attrs:{class:"token function"}},[t._v("older")]),e("span",{pre:!0,attrs:{class:"token punctuation"}},[t._v("(")]),e("span",{pre:!0,attrs:{class:"token keyword"}},[t._v("self")]),e("span",{pre:!0,attrs:{class:"token punctuation"}},[t._v(".")]),t._v("timelock"),e("span",{pre:!0,attrs:{class:"token punctuation"}},[t._v(")")]),e("span",{pre:!0,attrs:{class:"token punctuation"}},[t._v(")")]),e("span",{pre:!0,attrs:{class:"token punctuation"}},[t._v(")")]),e("span",{pre:!0,attrs:{class:"token punctuation"}},[t._v(")")]),t._v("\n    "),e("span",{pre:!0,attrs:{class:"token punctuation"}},[t._v("}")]),t._v("\n"),e("span",{pre:!0,attrs:{class:"token punctuation"}},[t._v("}")]),t._v("\n")])])]),e("h3",{attrs:{id:"a-new-repo-for-the-cli"}},[e("a",{staticClass:"header-anchor",attrs:{href:"#a-new-repo-for-the-cli"}},[t._v("#")]),t._v(" A new repo for the CLI")]),t._v(" "),e("p",[t._v("The "),e("code",[t._v("cli")]),t._v(" module (and it's related "),e("code",[t._v("cli-utils")]),t._v(" feature) have been removed from the main BDK repo and moved to their new home, the "),e("a",{attrs:{href:"https://github.com/bitcoindevkit/bdk-cli",target:"_blank",rel:"noopener noreferrer"}},[t._v("bdk-cli"),e("OutboundLink")],1),t._v(" repo. The APIs exposed were mainly used internally, for the "),e("code",[t._v("repl")]),t._v(" and the "),e("a",{attrs:{href:"/bdk-cli/playground"}},[t._v("playground")]),t._v("\nin our website, but in case you were using one of those keep that in mind.")]),t._v(" "),e("h2",{attrs:{id:"contributors"}},[e("a",{staticClass:"header-anchor",attrs:{href:"#contributors"}},[t._v("#")]),t._v(" Contributors")]),t._v(" "),e("p",[t._v("A huge thanks to everybody who contributed to this new release with suggestions, pull requests and bug reports.")]),t._v(" "),e("p",[t._v("Since the "),e("code",[t._v("v0.2.0")]),t._v(" release around a month ago, we've had "),e("code",[t._v("24")]),t._v(" new commits made by "),e("code",[t._v("6")]),t._v(" different contributors for a total of "),e("code",[t._v("404")]),t._v(" additions and "),e("code",[t._v("1243")]),t._v(" deletions. Here's the "),e("a",{attrs:{href:"https://github.com/bitcoindevkit/bdk/compare/v0.2.0...v0.3.0",target:"_blank",rel:"noopener noreferrer"}},[t._v("full diff"),e("OutboundLink")],1),t._v(".")]),t._v(" "),e("p",[t._v("A special thanks to the new contributor for this release:")]),t._v(" "),e("ul",[e("li",[e("a",{attrs:{href:"https://github.com/tcharding",target:"_blank",rel:"noopener noreferrer"}},[t._v("@tcharding"),e("OutboundLink")],1),t._v(" - Tobin C. Harding")])])])}),[],!1,null,null,null);s.default=n.exports}}]);