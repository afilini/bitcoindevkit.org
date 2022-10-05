(window.webpackJsonp=window.webpackJsonp||[]).push([[33],{350:function(e,t,o){"use strict";o.r(t);var a=o(6),i=Object(a.a)({},(function(){var e=this,t=e._self._c;return t("ContentSlotsDistributor",{attrs:{"slot-key":e.$parent.slotKey}},[t("p",[e._v("Over the past few months the work on "),t("a",{attrs:{href:"https://github.com/LLFourn/bdk_core_staging",target:"_blank",rel:"noopener noreferrer"}},[e._v("bdk_core"),t("OutboundLink")],1),e._v(" quietly continued behind the scenes, and as the time went on it started expanding beyond the scope of just improving the "),t("em",[e._v("syncing")]),e._v(" mechanism of BDK. Being a new fresh\nproject it allowed for iterating much faster, and we soon realized we could make large improvements to the general architecture of BDK to fix many of the issues and shortcomings found over time.")]),e._v(" "),t("p",[e._v("For this reason, we decided to move forward with the project and start planning the integration into BDK itself. This blog post will briefly describe the new concept for how BDK will be structured and lay down a plan\nfor the development in the next few months.")]),e._v(" "),t("h2",{attrs:{id:"goals"}},[t("a",{staticClass:"header-anchor",attrs:{href:"#goals"}},[e._v("#")]),e._v(" Goals")]),e._v(" "),t("p",[e._v("First of all, we should outline at least the main goals of BDK 1.0, ergo what we want to improve over the current state of the project.")]),e._v(" "),t("h3",{attrs:{id:"stable-api"}},[t("a",{staticClass:"header-anchor",attrs:{href:"#stable-api"}},[e._v("#")]),e._v(" Stable API")]),e._v(" "),t("p",[e._v("Ever since the "),t("code",[e._v("0.1.0")]),e._v(" release of BDK we've always broken the API with each release. Most of the time in minor and very contained ways, but in "),t("em",[e._v("some")]),e._v(" way nonetheless. One of the main sources of breakage have been\nthe "),t("code",[e._v("Blockchain")]),e._v(" and "),t("code",[e._v("Database")]),e._v(" traits. Those two together are used in essentially any operation a user may do on a "),t("code",[e._v("Wallet")]),e._v(", and are thus impacted by any relatively large change or new feature added to the code.")]),e._v(" "),t("p",[e._v("Want to "),t("a",{attrs:{href:"https://github.com/bitcoindevkit/bdk/pull/515",target:"_blank",rel:"noopener noreferrer"}},[e._v("keep track of whether a UTXO is spent"),t("OutboundLink")],1),e._v("? You need to change the "),t("code",[e._v("Database")]),e._v(" that stores this information. Want to "),t("a",{attrs:{href:"https://github.com/bitcoindevkit/bdk/pull/669",target:"_blank",rel:"noopener noreferrer"}},[e._v("know the timestamp of the latest block"),t("OutboundLink")],1),e._v("?\nYou need to change the "),t("code",[e._v("Blockchain")]),e._v(" trait to fetch that extra bit of information. And the list goes on and on.")]),e._v(" "),t("p",[e._v("Since making changes to these traits is always so painful for us and our downstream users, this ended up delaying or considerably slowing down the development of new features in BDK.")]),e._v(" "),t("p",[e._v("bdk_core tries to minimize the (ab)use of traits, and this will help immensely when trying to provide a stable API for our users.")]),e._v(" "),t("h3",{attrs:{id:"upstreaming-our-code"}},[t("a",{staticClass:"header-anchor",attrs:{href:"#upstreaming-our-code"}},[e._v("#")]),e._v(" Upstreaming our code")]),e._v(" "),t("p",[e._v("BDK internally implements many features that could be useful to other projects as well. While working on this integration we will also try to upstream some of our code to the relevant crates, mainly "),t("a",{attrs:{href:"https://github.com/rust-bitcoin/rust-miniscript",target:"_blank",rel:"noopener noreferrer"}},[t("code",[e._v("rust-miniscript")]),t("OutboundLink")],1),e._v(".")]),e._v(" "),t("p",[e._v("This has essentially three benefits:")]),e._v(" "),t("ol",[t("li",[e._v("A new set of eyes will take a look at the code, potentially spotting issues or suggesting improvements")]),e._v(" "),t("li",[e._v("This will lower the amount of code that we have to maintain ourselves")]),e._v(" "),t("li",[e._v("Other people can benefit from our code, which was previously tightly integrated into BDK and hard to re-use")])]),e._v(" "),t("h3",{attrs:{id:"partially-syncing-a-wallet"}},[t("a",{staticClass:"header-anchor",attrs:{href:"#partially-syncing-a-wallet"}},[e._v("#")]),e._v(" Partially Syncing a Wallet")]),e._v(" "),t("p",[e._v("This single point was the main reason the bdk_core project was kickstarted, and it means giving our users the ability to incrementally sync a wallet over time instead of working in single big batches.")]),e._v(" "),t("p",[e._v("This is explained very well in the "),t("RouterLink",{attrs:{to:"/blog/bdk-core-pt1/"}},[e._v("first bdk_core post")]),e._v(", so I won't go into details here. Think of this as a much more flexible way to sync a wallet, which in turn will allow us to simplify our current implementation\nof blockchain backends like compact block filters, and also offer a better API for our users.")],1),e._v(" "),t("h3",{attrs:{id:"no-std"}},[t("a",{staticClass:"header-anchor",attrs:{href:"#no-std"}},[e._v("#")]),e._v(" "),t("code",[e._v("no_std")])]),e._v(" "),t("p",[e._v("bdk_core is built with "),t("code",[e._v("no_std")]),e._v(" in mind since the beginning, something we've been wanting to support in BDK "),t("a",{attrs:{href:"https://github.com/bitcoindevkit/bdk/issues/205",target:"_blank",rel:"noopener noreferrer"}},[e._v("for a long time"),t("OutboundLink")],1),e._v('. Being more modular means the "core" module doesn\'t really need that many dependencies,\nand this really simplifies the '),t("code",[e._v("no_std")]),e._v(" work.")]),e._v(" "),t("p",[e._v("This will allow the main components of BDK to work on embedded hardware as well, making it possible to use the library as a foundation for any Bitcoin hardware device like hardware wallets.")]),e._v(" "),t("h3",{attrs:{id:"lower-msrv"}},[t("a",{staticClass:"header-anchor",attrs:{href:"#lower-msrv"}},[e._v("#")]),e._v(" Lower MSRV")]),e._v(" "),t("p",[e._v("Removing many of our current dependencies from the core components of BDK will also allow us to lower our MSRV considerably, which in turn will allow BDK to compile on older distros or entirely different toolchains like\n"),t("a",{attrs:{href:"https://github.com/thepowersgang/mrustc",target:"_blank",rel:"noopener noreferrer"}},[t("code",[e._v("mrustc")]),t("OutboundLink")],1),e._v(", which usually don't keep up with "),t("code",[e._v("rustc")]),e._v(" in terms of language features.")]),e._v(" "),t("h2",{attrs:{id:"architecture"}},[t("a",{staticClass:"header-anchor",attrs:{href:"#architecture"}},[e._v("#")]),e._v(" Architecture")]),e._v(" "),t("p",[e._v("Roughly speaking, after integrating bdk_core into BDK the architecture will look like this:")]),e._v(" "),t("ul",[t("li",[e._v("bdk_core: this crate will contain all the low level components of a Bitcoin wallet. For example, using this low level API it will be possible to keep track of arbitrary scripts (without the limitations"),t("sup",{staticClass:"footnote-ref"},[t("a",{attrs:{href:"#fn1",id:"fnref1"}},[e._v("[1]")])]),e._v("\nof descriptors) or apply individual blocks to the state of the wallet")]),e._v(" "),t("li",[e._v("bdk_compat: this crate will use the components provided by bdk_core to implement a descriptor-based wallet that supports up to two "),t("em",[e._v("keychains")]),e._v(", like our current "),t("code",[e._v("Wallet")]),e._v(" implementation does. It will allow our\nusers to upgrade to BDK 1.0 with minimal changes to their code, but being a compatibility layer it will probably lack many of the advanced features that bdk_core brings to the table")]),e._v(" "),t("li",[e._v("bdk_"),t("em",[e._v("<blockchain>")]),e._v(": the blockchain backends like Esplora, Electrum, RPC, will be moved into individual separate crates that users can decide to include individually")])]),e._v(" "),t("h2",{attrs:{id:"timeline"}},[t("a",{staticClass:"header-anchor",attrs:{href:"#timeline"}},[e._v("#")]),e._v(" Timeline")]),e._v(" "),t("p",[e._v("We can't provide a precise timeline because it's a big development effort and it also depends on some relatively large PRs making into upstream project. That said, here's our rough plan:")]),e._v(" "),t("ol",[t("li",[e._v("October: during this month we will work on opening a PR to integrate bdk_core into BDK")]),e._v(" "),t("li",[e._v("November: review of the PR, work on upstreaming our code to "),t("code",[e._v("rust-miniscript")])]),e._v(" "),t("li",[e._v("December: finishing touches, examples, documentation")])]),e._v(" "),t("h2",{attrs:{id:"feature-freezing-bdk"}},[t("a",{staticClass:"header-anchor",attrs:{href:"#feature-freezing-bdk"}},[e._v("#")]),e._v(" Feature Freezing BDK")]),e._v(" "),t("p",[e._v("With our focus shifting to bdk_core we are officially "),t("em",[e._v("feature freezing")]),e._v(" BDK starting from release "),t("code",[e._v("0.23")]),e._v(" (which will be published on October 6th). This means that we won't be adding any new features to BDK until the\nintegration is completed, because it takes a lot of effort to implement and/or review them, and there's the risk that most of the code will have to be re-done or thrown away anyway when moving to bdk_core.")]),e._v(" "),t("p",[e._v("A notable exception to this rule will be the upcoming "),t("a",{attrs:{href:"https://github.com/bitcoindevkit/bdk/pull/770",target:"_blank",rel:"noopener noreferrer"}},[e._v("upgrade to "),t("code",[e._v("rust-bitcoin")]),e._v(" "),t("code",[e._v("0.29")]),t("OutboundLink")],1),e._v(", which is now planned for the release "),t("code",[e._v("0.24")]),e._v(" since "),t("code",[e._v("rust-miniscript")]),e._v(" "),t("code",[e._v("8.0.0")]),e._v(" hasn't been released in time for "),t("code",[e._v("0.23")]),e._v(".")]),e._v(" "),t("p",[e._v("During this feature freeze period we will keep maintaining the library, updating our dependencies, fixing bugs and making releases accordingly.")]),e._v(" "),t("h2",{attrs:{id:"conclusion"}},[t("a",{staticClass:"header-anchor",attrs:{href:"#conclusion"}},[e._v("#")]),e._v(" Conclusion")]),e._v(" "),t("p",[e._v("This is an exciting new development for BDK, a well needed refresh to an architecture that hasn't changed much over time, but that it's starting to show its age. This integration will open up so many new possibilities\nfor our downstream users, and it's a major step towards our goal of providing simple, yet powerful tools for Bitcoin developers 🚀.")]),e._v(" "),t("hr",{staticClass:"footnotes-sep"}),e._v(" "),t("section",{staticClass:"footnotes"},[t("ol",{staticClass:"footnotes-list"},[t("li",{staticClass:"footnote-item",attrs:{id:"fn1"}},[t("p",[e._v("Not every script can be expressed as descriptor "),t("a",{staticClass:"footnote-backref",attrs:{href:"#fnref1"}},[e._v("↩︎")])])])])])])}),[],!1,null,null,null);t.default=i.exports}}]);