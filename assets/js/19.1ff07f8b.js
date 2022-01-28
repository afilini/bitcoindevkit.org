(window.webpackJsonp=window.webpackJsonp||[]).push([[19],{439:function(e,t,r){"use strict";r.r(t);var a=r(18),s=Object(a.a)({},(function(){var e=this,t=e.$createElement,r=e._self._c||t;return r("ContentSlotsDistributor",{attrs:{"slot-key":e.$parent.slotKey}},[r("p",[e._v("I have tried to setup a 2 of 2 multi signature infrastructure with two\ndifferent wallets, which know nothing about each other, but are compliant with\ntwo very important protocols: "),r("a",{attrs:{href:"https://bitcoinops.org/en/topics/output-script-descriptors/",target:"_blank",rel:"noopener noreferrer"}},[e._v("Output Descriptors"),r("OutboundLink")],1),e._v(" and "),r("a",{attrs:{href:"https://en.bitcoin.it/wiki/BIP_0174",target:"_blank",rel:"noopener noreferrer"}},[e._v("Partially Signed\nBitcoin Transactions"),r("OutboundLink")],1),e._v(" described in BIP 174.")]),e._v(" "),r("p",[e._v("Before these two protocols came into existence, making a multi signature setup\nand spending from it was possible only if the involved parties were using the\nsame wallet (eg. Electrum Desktop Wallet). This limitation was due to the fact\nthat the two parties had to agree:")]),e._v(" "),r("ul",[r("li",[e._v("on the particular type of script and address to use")]),e._v(" "),r("li",[e._v("on the way the transaction would be shared composed and signed with all the\ninvolved parties.")])]),e._v(" "),r("p",[r("a",{attrs:{href:"https://bitcoinops.org/en/topics/output-script-descriptors/",target:"_blank",rel:"noopener noreferrer"}},[e._v("Output Descriptors"),r("OutboundLink")],1),e._v(" are a way to express which kind scriptPubKey and\naddresses to produce with a key or a series of keys.")]),e._v(" "),r("p",[r("a",{attrs:{href:"https://en.bitcoin.it/wiki/BIP_0174",target:"_blank",rel:"noopener noreferrer"}},[e._v("PSBT"),r("OutboundLink")],1),e._v(" is instead the standard protocol used to create a transaction and to enrich\nit with the necessary signatures and other components, to make it valid and complete.")]),e._v(" "),r("p",[e._v("Together they provide a common ground to create and use a multi signature\ninfrastructure in a heterogeneous environment, and this is what I have put\nto test.")]),e._v(" "),r("h2",{attrs:{id:"the-use-case"}},[r("a",{staticClass:"header-anchor",attrs:{href:"#the-use-case"}},[e._v("#")]),e._v(" The use case")]),e._v(" "),r("p",[e._v("Imagine Alice and Bob owning a company and being willing to put the corporate cash\nin a 2of2 multi signature setup, so that each one of them have to agree and sign each\ntransaction.")]),e._v(" "),r("h2",{attrs:{id:"the-role-of-descriptors"}},[r("a",{staticClass:"header-anchor",attrs:{href:"#the-role-of-descriptors"}},[e._v("#")]),e._v(" The role of Descriptors")]),e._v(" "),r("p",[e._v("If Alice and Bob cannot agree on the software to use, to monitor the same financial\nsituation, the two software must control and produce exactly the same series\nof multisignature addresses.")]),e._v(" "),r("p",[e._v("To make two different software produce the same addresses in a deterministic way\nwe must ensure that they:")]),e._v(" "),r("ul",[r("li",[e._v("produce the same pair of public keys")]),e._v(" "),r("li",[e._v("combine them in the same order")]),e._v(" "),r("li",[e._v("put them inside the same scriptPubKey to produce the same address")])]),e._v(" "),r("p",[e._v("Here is where the "),r("a",{attrs:{href:"https://bitcoinops.org/en/topics/output-script-descriptors/",target:"_blank",rel:"noopener noreferrer"}},[e._v("Output Descriptors"),r("OutboundLink")],1),e._v(" come into play. They describe:")]),e._v(" "),r("ul",[r("li",[e._v("the sequence of public keys each extended key (xpub) will produce")]),e._v(" "),r("li",[e._v("the sequence in which the new public keys of various parties will enter into\nthe script")]),e._v(" "),r("li",[e._v("the type of script the wallet will prepare with that group keys and so the type\nof address the group of keys will produce.")])]),e._v(" "),r("p",[r("strong",[e._v("By sharing the same Descriptor, every compliant wallet will derive\ndeterministically the same series of multisig addresses")]),e._v(".")]),e._v(" "),r("p",[e._v("Imagine Alice using Bitcoin Core (from now on "),r("a",{attrs:{href:"https://bitcoincore.org/",target:"_blank",rel:"noopener noreferrer"}},[e._v('"Core"'),r("OutboundLink")],1),e._v(') as a\nWallet and Bob using a "Last generation" wallet, Bitcoin Development Kit\n(from now on '),r("a",{attrs:{href:"https://bitcoindevkit.org/",target:"_blank",rel:"noopener noreferrer"}},[e._v('"BDK"'),r("OutboundLink")],1),e._v("), which uses descriptors and miniscript natively.")]),e._v(" "),r("p",[e._v("Each of these two software wallets should be able to:")]),e._v(" "),r("ul",[r("li",[e._v("Create a new address which is seen as belonging to the multi signature\nwallet in both software")]),e._v(" "),r("li",[e._v("Express the consent of each party by partially signing the transaction in a way\nthe other wallet can understand and complete it with its own signature.")])]),e._v(" "),r("p",[e._v("The infrastructure of multiple Extended keys combined toghether to produce\nmultiple multisignature addresses is often referred as\n"),r("em",[r("a",{attrs:{href:"https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki",target:"_blank",rel:"noopener noreferrer"}},[e._v("Hierarchical Deterministic"),r("OutboundLink")],1),e._v(" multi signature wallet or HDM")]),e._v(".")]),e._v(" "),r("p",[e._v("What follows are the steps to create the HDM usable both in Core and\nin BDK.")]),e._v(" "),r("p",[r("em",[e._v("Note: In Core, "),r("a",{attrs:{href:"https://github.com/bitcoin/bitcoin/pull/16528",target:"_blank",rel:"noopener noreferrer"}},[e._v("Descriptor wallets"),r("OutboundLink")],1),e._v(" are still experimental and in general,\nboth wallets should be tested for descriptor capabilities only in testnet.")])]),e._v(" "),r("h2",{attrs:{id:"our-playground"}},[r("a",{staticClass:"header-anchor",attrs:{href:"#our-playground"}},[e._v("#")]),e._v(" Our playground")]),e._v(" "),r("p",[e._v("We will build a 2of2 key set up that will be used cooperatively by Bitcoin Core\nand Bitcoin Development Kit.\nThe steps Alice and Bob will do are:")]),e._v(" "),r("ol",[r("li",[e._v("creation of the seed and the derived Extended Master Public and send it to\nthe other party")]),e._v(" "),r("li",[e._v("Create the multi signature descriptor for each wallet")]),e._v(" "),r("li",[e._v("Use each other's software to receive testnet coins from a faucet")]),e._v(" "),r("li",[e._v("return part of the coins to the faucet signing the transaction with both\nwallets.")])]),e._v(" "),r("p",[e._v("We need:")]),e._v(" "),r("ul",[r("li",[r("a",{attrs:{href:"https://bitcoindevkit.org/",target:"_blank",rel:"noopener noreferrer"}},[e._v("Bitcoin Dev Kit"),r("OutboundLink")],1)]),e._v(" "),r("li",[r("a",{attrs:{href:"https://bitcoincore.org/",target:"_blank",rel:"noopener noreferrer"}},[e._v("Bitcoin Core"),r("OutboundLink")],1),e._v(" (v0.21.0 or later)")])]),e._v(" "),r("h3",{attrs:{id:"1-creating-the-seeds-and-the-derived-extended-public-keys"}},[r("a",{staticClass:"header-anchor",attrs:{href:"#1-creating-the-seeds-and-the-derived-extended-public-keys"}},[e._v("#")]),e._v(" 1. Creating the seeds and the derived Extended Public keys")]),e._v(" "),r("h4",{attrs:{id:"seeds-and-extended-master-public"}},[r("a",{staticClass:"header-anchor",attrs:{href:"#seeds-and-extended-master-public"}},[e._v("#")]),e._v(" Seeds and Extended Master Public")]),e._v(" "),r("p",[e._v("We build an Extended Private Master Key for both wallet and derive a BIP84\nExtended Master Public for Bitcoin Core and then for BDK.")]),e._v(" "),r("p",[e._v("For Bitcoin Core (Alice):")]),e._v(" "),r("div",{staticClass:"language- extra-class"},[r("pre",{pre:!0,attrs:{class:"language-text"}},[r("code",[e._v("# new Extended wallet data\nexport core_key=$(bdk-cli key generate)\n\n# New Extended Master Private\n\nexport core_xprv=$(echo $core_key | jq -r '.xprv')\n\n# Now I derive the xpubs (one for receiving and one for the change)\n# together with informations about the derivation path to be communicated\n# to BDK wallet's owner (Bob).\n\nexport core_xpub_84_for_rec_desc=$(bdk-cli key derive --path m/84h/0h/0h/0 --xprv $core_xprv | jq -r '.xpub')\nexport core_xpub_84_for_chg_desc=$(bdk-cli key derive --path m/84h/0h/0h/1 --xprv $core_xprv | jq -r '.xpub')\n")])])]),r("p",[e._v("For BDK (Bob) we do the same:")]),e._v(" "),r("div",{staticClass:"language- extra-class"},[r("pre",{pre:!0,attrs:{class:"language-text"}},[r("code",[e._v("# new Extended wallet data\n\nexport BDK_key=$(bdk-cli key generate)\n\n# New Extended Master Private\n\nexport BDK_xprv=$(echo $BDK_key | jq -r '.xprv')\n\n# Now I build the derived xpubs to be communicated (to Alice).\n\nexport BDK_xpub_84_for_rec_desc=$(bdk-cli key derive --path m/84h/0h/0h/0 --xprv $BDK_xprv | jq -r '.xpub')\nexport BDK_xpub_84_for_chg_desc=$(bdk-cli key derive --path m/84h/0h/0h/1 --xprv $BDK_xprv | jq -r '.xpub')\n")])])]),r("h3",{attrs:{id:"2-creation-of-the-multi-signature-descriptor-for-each-wallet"}},[r("a",{staticClass:"header-anchor",attrs:{href:"#2-creation-of-the-multi-signature-descriptor-for-each-wallet"}},[e._v("#")]),e._v(" 2. Creation of the multi signature descriptor for each wallet")]),e._v(" "),r("p",[e._v("To build a multisig wallet, each wallet owner must compose the descriptor\nadding:")]),e._v(" "),r("ul",[r("li",[e._v("his derived extended "),r("strong",[e._v("private")]),e._v(" key AND")]),e._v(" "),r("li",[e._v("all the extended "),r("strong",[e._v("public")]),e._v(" keys of the other wallets involved in the\nmulti signature setup")])]),e._v(" "),r("p",[r("em",[e._v("The different nature of the two keys (one is private and one is public) is\ndue to the fact that each wallet, to be able to partially sign the transaction,\n"),r("strong",[e._v("must manage the private key of the wallet's owner")])]),e._v(" AND have the other\nparty's public key. Otherwise, if we put both public keys, we would obtain\na watch-only wallet unable to sign the transactions. If we\nhad both extended private keys inside the descriptor, we would allow each party\nto finalize the transactions autonomously.")]),e._v(" "),r("h4",{attrs:{id:"in-bitcoin-core"}},[r("a",{staticClass:"header-anchor",attrs:{href:"#in-bitcoin-core"}},[e._v("#")]),e._v(" In Bitcoin Core:")]),e._v(" "),r("p",[e._v("In our case, the multi signature descriptor for Bitcoin Core will be composed\nwith:")]),e._v(" "),r("ul",[r("li",[e._v("The BIP84 derived Extended "),r("strong",[e._v("Public")]),e._v(" Key from BDK")]),e._v(" "),r("li",[e._v("The BIP84 derived Extended "),r("strong",[e._v("Private")]),e._v(" Key from Core.")])]),e._v(" "),r("p",[e._v("BDK wallet's owner will send to Core's owner the derived xpub for this purpose.\nThis is how the Core's multisig descriptor will be created and put into an\nenvironment variable:")]),e._v(" "),r("div",{staticClass:"language- extra-class"},[r("pre",{pre:!0,attrs:{class:"language-text"}},[r("code",[e._v("export core_rec_desc=\"wsh(multi(2,$BDK_xpub_84_for_rec_desc,$core_xprv/84'/0'/0'/0/*))\"\n")])])]),r("p",[e._v("Where of course "),r("code",[e._v("$BDK_xpub_84_for_rec_desc")]),e._v("is the derived master public created\nin BDK and received by Core's owner.")]),e._v(" "),r("p",[e._v("The meaning of what is before and after is illustrated in the doc that explain\nthe use of "),r("a",{attrs:{href:"https://bitcoinops.org/en/topics/output-script-descriptors/",target:"_blank",rel:"noopener noreferrer"}},[e._v("Output Descriptors in Bitcoin Core"),r("OutboundLink")],1),e._v(".")]),e._v(" "),r("p",[e._v("We add the necessary checksum using the specific "),r("code",[e._v("bitcoin-cli")]),e._v(" call.")]),e._v(" "),r("div",{staticClass:"language- extra-class"},[r("pre",{pre:!0,attrs:{class:"language-text"}},[r("code",[e._v("export core_rec_desc_chksum=$core_rec_desc#$(bitcoin-cli -testnet getdescriptorinfo $core_rec_desc | jq -r '.checksum')\n")])])]),r("p",[e._v("We repeat the same to build the descriptor to receive the change.")]),e._v(" "),r("div",{staticClass:"language- extra-class"},[r("pre",{pre:!0,attrs:{class:"language-text"}},[r("code",[e._v("export core_chg_desc=\"wsh(multi(2,$BDK_xpub_84_for_chg_desc,$core_xprv/84'/0'/0'/1/*))\"\nexport core_chg_desc_chksum=$core_chg_desc#$(bitcoin-cli -testnet getdescriptorinfo $core_chg_desc|jq -r '.checksum')\n")])])]),r("h4",{attrs:{id:"in-bdk"}},[r("a",{staticClass:"header-anchor",attrs:{href:"#in-bdk"}},[e._v("#")]),e._v(" In BDK:")]),e._v(" "),r("p",[e._v("For BDK we set the derivation for receiving addresses and change addresses\nin the command line (maybe setting an alias)")]),e._v(" "),r("p",[e._v("Building the descriptor:")]),e._v(" "),r("div",{staticClass:"language- extra-class"},[r("pre",{pre:!0,attrs:{class:"language-text"}},[r("code",[e._v("export BDK_rec_desc=\"wsh(multi(2,$BDK_xprv/84'/0'/0'/0/*,$core_xpub_84_for_rec_desc))\"`\n")])])]),r("p",[e._v("Please note that the order of the extended key in the descriptor MUST be the\nsame in the 2 wallets.")]),e._v(" "),r("p",[r("em",[e._v("We have chosen to put BDK first and in each software wallet, the public key\nderived from BDK will always come first. In alternative, we could have chosen to\nproduce the descriptor, "),r("a",{attrs:{href:"https://github.com/bitcoin/bitcoin/pull/17056?ref=tokendaily",target:"_blank",rel:"noopener noreferrer"}},[e._v("chosing a "),r("code",[e._v("soretedmulti")]),e._v(" multisignature setup"),r("OutboundLink")],1)]),e._v(".")]),e._v(" "),r("div",{staticClass:"language- extra-class"},[r("pre",{pre:!0,attrs:{class:"language-text"}},[r("code",[e._v("export BDK_rec_desc_chksum=$BDK_rec_desc#$(bitcoin-cli -testnet getdescriptorinfo $BDK_rec_desc | jq -r '.checksum')\nexport BDK_chg_desc=\"wsh(multi(2,$BDK_xprv/84'/0'/0'/1/*,$core_xpub_84_for_chg_desc))\"\nexport BDK_chg_desc_chksum=$BDK_chg_desc#$(bitcoin-cli -testnet getdescriptorinfo $BDK_chg_desc | jq -r '.checksum')\n")])])]),r("p",[e._v("To take a look at the variables we have produced so far:")]),e._v(" "),r("div",{staticClass:"language- extra-class"},[r("pre",{pre:!0,attrs:{class:"language-text"}},[r("code",[e._v("env  | grep 'core_'\nenv  | grep 'BDK_'\n")])])]),r("p",[e._v("Now we will use the multisig descriptor wallet to receive testnet coins with\nAlice and Bob's software")]),e._v(" "),r("h3",{attrs:{id:"3-use-each-others-software-to-receive-testnet-coins-from-a-faucet"}},[r("a",{staticClass:"header-anchor",attrs:{href:"#3-use-each-others-software-to-receive-testnet-coins-from-a-faucet"}},[e._v("#")]),e._v(" 3. Use each other's software to receive testnet coins from a faucet")]),e._v(" "),r("h4",{attrs:{id:"in-bitcoin-core-2"}},[r("a",{staticClass:"header-anchor",attrs:{href:"#in-bitcoin-core-2"}},[e._v("#")]),e._v(" In Bitcoin Core")]),e._v(" "),r("p",[e._v('Alice must create an empty, experimental new "descriptors wallet" in Core and\nto import the multisig Output Descriptor.')]),e._v(" "),r("div",{staticClass:"language- extra-class"},[r("pre",{pre:!0,attrs:{class:"language-text"}},[r("code",[e._v('bitcoin-cli -testnet createwallet "multisig2of2withBDK" false true "" false true false\n')])])]),r("p",[e._v("The flag are to:")]),e._v(" "),r("ul",[r("li",[e._v("use the private keys")]),e._v(" "),r("li",[e._v("make it empty")]),e._v(" "),r("li",[e._v("no password provided to the wallet")]),e._v(" "),r("li",[e._v("reusing of addresses not allowed")]),e._v(" "),r("li",[e._v('"new experimental descriptors wallet"')]),e._v(" "),r("li",[e._v("don't load it on start up")])]),e._v(" "),r("div",{staticClass:"language- extra-class"},[r("pre",{pre:!0,attrs:{class:"language-text"}},[r("code",[e._v('bitcoin-cli -testnet -rpcwallet=multisig2of2withBDK importdescriptors "[{\\"desc\\":\\"$core_rec_desc_chksum\\",\\"timestamp\\":\\"now\\",\\"active\\":true,\\"internal\\":false},{\\"desc\\":\\"$core_chg_desc_chksum\\",\\"timestamp\\":\\"now\\",\\"active\\":true,\\"internal\\":true}]"\n')])])]),r("p",[e._v("Now Alice asks for her first receiving multisignature address.")]),e._v(" "),r("div",{staticClass:"language- extra-class"},[r("pre",{pre:!0,attrs:{class:"language-text"}},[r("code",[e._v("export first_address=$(bitcoin-cli -testnet -rpcwallet=multisig2of2withBDK getnewaddress)\necho $first_address\n")])])]),r("h4",{attrs:{id:"bdk"}},[r("a",{staticClass:"header-anchor",attrs:{href:"#bdk"}},[e._v("#")]),e._v(" BDK")]),e._v(" "),r("p",[e._v("In BDK Bob can specify directly the descriptors on the command line to produce\nthe multisig address, because BDK is descriptors aware natively.")]),e._v(" "),r("div",{staticClass:"language- extra-class"},[r("pre",{pre:!0,attrs:{class:"language-text"}},[r("code",[e._v('repl -d "$BDK_rec_desc_chksum" -c "$BDK_chg_desc_chksum" -n testnet -w $BDK_fingerprint get_new_address`\n')])])]),r("p",[e._v('Et voilà: if we have done everything correctly, the newly created address in\nCore is the same of the newly created address in BDK. this is part of the\n"miracle" of descriptors\' interoperability.')]),e._v(" "),r("h4",{attrs:{id:"we-ask-for-testnet-coins-giving-the-first-created-address"}},[r("a",{staticClass:"header-anchor",attrs:{href:"#we-ask-for-testnet-coins-giving-the-first-created-address"}},[e._v("#")]),e._v(" We ask for testnet coins giving the first created address.")]),e._v(" "),r("p",[e._v('To find testnet coins for free, you can just google "testnet faucet" and you\nshould find some satoshis to play with. Just give to the site your first\ngenerated address and, in twenty minutes, you will find the satoshis in\nyour balance both in Core and in BDK.')]),e._v(" "),r("div",{staticClass:"language- extra-class"},[r("pre",{pre:!0,attrs:{class:"language-text"}},[r("code",[e._v('# to check it in Core:\n\nbitcoin-cli -testnet -rpcwallet=multisig2of2withBDK getbalance\n\n# In BDK:\n\n# Sync with the blockchain\nrepl -d "$BDK_rec_desc_chksum" -c "$BDK_chg_desc_chksum" -n testnet -w $BDK_fingerprint sync\n# Get the balance\nrepl -d "$BDK_rec_desc_chksum" -c "$BDK_chg_desc_chksum" -n testnet -w $BDK_fingerprint get_balance\n')])])]),r("p",[e._v("Some testnet faucets have an address to send back the unused satoshi after\nthe use. Take note of that because we will use it in the next step.")]),e._v(" "),r("h3",{attrs:{id:"4-we-return-part-of-the-satoshis-received-back-to-the-faucet"}},[r("a",{staticClass:"header-anchor",attrs:{href:"#4-we-return-part-of-the-satoshis-received-back-to-the-faucet"}},[e._v("#")]),e._v(" 4. we return part of the satoshis received back to the faucet")]),e._v(" "),r("div",{staticClass:"language- extra-class"},[r("pre",{pre:!0,attrs:{class:"language-text"}},[r("code",[e._v('export psbt=$(bitcoin-cli -testnet -rpcwallet=multisig2of2withBDK walletcreatefundedpsbt "[]" "[{\\"tb1qrcesfj9f2d7x40xs6ztnlrcgxhh6vsw8658hjdhdy6qgkf6nfrds9rp79a\\":0.000012}]" | jq -r \'.psbt\')\n\nexport psbt=$(bitcoin-cli -testnet -rpcwallet=multisig2of2withBDK walletprocesspsbt $psbt | jq -r \'.psbt\')\n{\n  "psbt": "cHNidP8BAIkCAAAAATj90EC+NAuXj7y6SseZJucoJM6sGnUcVm9koTveZECTAAAAAAD+////AmACAAAAAAAAIgAg98ol9j4AalD71E0mV5QV0uM6/vCT+pi2twxr/zrvLROwBAAAAAAAACIAIB4zBMipU3xqvNDQlz+PCDXvpkHH1Q95Nu0mgIsnU0jbAAAAAAABAIkCAAAAAQS+ObgGG6UwtvaO3KYph2E3/ws7Q83RbmR3rxC0fKYSAQAAAAD+////AtAHAAAAAAAAIgAg6GXadcNj7k4yKUbnVlTLiedXQFXYdCBoNygop/PISNDAHQAAAAAAACIAIBQpiDTgPIMt0ld8cmuYqlY+EIPjvrmMqZruDhs61hQNAAAAAAEBK9AHAAAAAAAAIgAg6GXadcNj7k4yKUbnVlTLiedXQFXYdCBoNygop/PISNAiAgNt0j7Ae0iA7qlLolruNqLWkPA96J0qgMLK1M7WOGMAfUcwRAIgS6x0i1J1HRzllIPf4WlFY+Dl8kCCLK81TL2djZxTFXMCICJVBKkKNxu1w1mRVor6iFTSVXiJjmWwBXVeJLISvBwAAQEFR1IhArn3tec7n7318rnWqf0dIIwtLtfxo6Zt0HV70UvZYaWvIQNt0j7Ae0iA7qlLolruNqLWkPA96J0qgMLK1M7WOGMAfVKuIgYCufe15zufvfXyudap/R0gjC0u1/Gjpm3QdXvRS9lhpa8YNEw2cFQAAIAAAACAAAAAgAAAAAAAAAAAIgYDbdI+wHtIgO6pS6Ja7jai1pDwPeidKoDCytTO1jhjAH0YO/laXFQAAIAAAACAAAAAgAAAAAAAAAAAAAEBR1IhAqccvA3rL13D1K4GeWjcahDsO3P8oaVNBttk4MlCKXIcIQLHKhjmPuCQjyS77ZfaMN2tdgNKcf/+57VXGZhz/UWTl1KuIgICpxy8DesvXcPUrgZ5aNxqEOw7c/yhpU0G22TgyUIpchwYNEw2cFQAAIAAAACAAAAAgAEAAAADAAAAIgICxyoY5j7gkI8ku+2X2jDdrXYDSnH//ue1VxmYc/1Fk5cYO/laXFQAAIAAAACAAAAAgAEAAAADAAAAAAA=",\n  "complete": false\n}\n')])])]),r("p",[e._v("Exactly! Note the "),r("code",[e._v('"complete": false')]),e._v(". We have processed the transaction with\nCore but we miss one of the necessary key of the multisig 2of2 setup (The one\ncontained inside BDK).")]),e._v(" "),r("p",[r("code",[e._v("tb1qrcesfj9f2d7x40xs6ztnlrcgxhh6vsw8658hjdhdy6qgkf6nfrds9rp79a")]),e._v(" is the address\nwe got from the faucet site to return the satoshis.")]),e._v(" "),r("p",[e._v("The "),r("a",{attrs:{href:"https://en.bitcoin.it/wiki/BIP_0174",target:"_blank",rel:"noopener noreferrer"}},[e._v("PSBT"),r("OutboundLink")],1),e._v(" is sent over to the BDK wallet owner who tries to sign the\ntransaction:")]),e._v(" "),r("div",{staticClass:"language- extra-class"},[r("pre",{pre:!0,attrs:{class:"language-text"}},[r("code",[e._v('repl -d "$BDK_rec_desc_chksum" -c "$BDK_chg_desc_chksum" -n testnet -w $BDK_fingerprint sign --psbt $psbt\n{\n  "is_finalized": true,\n  "psbt": "cHNidP8BAIkCAAAAATj90EC+NAuXj7y6SseZJucoJM6sGnUcVm9koTveZECTAAAAAAD+////AmACAAAAAAAAIgAg98ol9j4AalD71E0mV5QV0uM6/vCT+pi2twxr/zrvLROwBAAAAAAAACIAIB4zBMipU3xqvNDQlz+PCDXvpkHH1Q95Nu0mgIsnU0jbAAAAAAABAIkCAAAAAQS+ObgGG6UwtvaO3KYph2E3/ws7Q83RbmR3rxC0fKYSAQAAAAD+////AtAHAAAAAAAAIgAg6GXadcNj7k4yKUbnVlTLiedXQFXYdCBoNygop/PISNDAHQAAAAAAACIAIBQpiDTgPIMt0ld8cmuYqlY+EIPjvrmMqZruDhs61hQNAAAAAAEBK9AHAAAAAAAAIgAg6GXadcNj7k4yKUbnVlTLiedXQFXYdCBoNygop/PISNAiAgNt0j7Ae0iA7qlLolruNqLWkPA96J0qgMLK1M7WOGMAfUcwRAIgS6x0i1J1HRzllIPf4WlFY+Dl8kCCLK81TL2djZxTFXMCICJVBKkKNxu1w1mRVor6iFTSVXiJjmWwBXVeJLISvBwAASICArn3tec7n7318rnWqf0dIIwtLtfxo6Zt0HV70UvZYaWvRzBEAiBkVDLgVEwvENnLx+04o7gGpGjFDBwAXTJmf8Yvo35oygIgbuBkHsvPC9jmZcMZ9P+Pwp01yxSaWo+5feyPmd3ai1kBAQVHUiECufe15zufvfXyudap/R0gjC0u1/Gjpm3QdXvRS9lhpa8hA23SPsB7SIDuqUuiWu42otaQ8D3onSqAwsrUztY4YwB9Uq4iBgNt0j7Ae0iA7qlLolruNqLWkPA96J0qgMLK1M7WOGMAfRg7+VpcVAAAgAAAAIAAAACAAAAAAAAAAAAiBgK597XnO5+99fK51qn9HSCMLS7X8aOmbdB1e9FL2WGlrxg0TDZwVAAAgAAAAIAAAACAAAAAAAAAAAABBwABCNoEAEcwRAIgZFQy4FRMLxDZy8ftOKO4BqRoxQwcAF0yZn/GL6N+aMoCIG7gZB7LzwvY5mXDGfT/j8KdNcsUmlqPuX3sj5nd2otZAUcwRAIgS6x0i1J1HRzllIPf4WlFY+Dl8kCCLK81TL2djZxTFXMCICJVBKkKNxu1w1mRVor6iFTSVXiJjmWwBXVeJLISvBwAAUdSIQK597XnO5+99fK51qn9HSCMLS7X8aOmbdB1e9FL2WGlryEDbdI+wHtIgO6pS6Ja7jai1pDwPeidKoDCytTO1jhjAH1SrgABAUdSIQKnHLwN6y9dw9SuBnlo3GoQ7Dtz/KGlTQbbZODJQilyHCECxyoY5j7gkI8ku+2X2jDdrXYDSnH//ue1VxmYc/1Fk5dSriICAqccvA3rL13D1K4GeWjcahDsO3P8oaVNBttk4MlCKXIcGDRMNnBUAACAAAAAgAAAAIABAAAAAwAAACICAscqGOY+4JCPJLvtl9ow3a12A0px//7ntVcZmHP9RZOXGDv5WlxUAACAAAAAgAAAAIABAAAAAwAAAAAA"\n}\n')])])]),r("p",[e._v('The signature has succeded (note the "is_finalized": true,) and now we can\nbroadcast the transction.')]),e._v(" "),r("div",{staticClass:"language- extra-class"},[r("pre",{pre:!0,attrs:{class:"language-text"}},[r("code",[e._v('repl -d "$BDK_rec_desc_chksum" -c "$BDK_chg_desc_chksum" -n testnet -w $BDK_fingerprint broadcast --psbt "cHNidP8BAIkCAAAAATj90EC+NAuXj7y6SseZJucoJM6sGnUcVm9koTveZECTAAAAAAD+////AmACAAAAAAAAIgAg98ol9j4AalD71E0mV5QV0uM6/vCT+pi2twxr/zrvLROwBAAAAAAAACIAIB4zBMipU3xqvNDQlz+PCDXvpkHH1Q95Nu0mgIsnU0jbAAAAAAABAIkCAAAAAQS+ObgGG6UwtvaO3KYph2E3/ws7Q83RbmR3rxC0fKYSAQAAAAD+////AtAHAAAAAAAAIgAg6GXadcNj7k4yKUbnVlTLiedXQFXYdCBoNygop/PISNDAHQAAAAAAACIAIBQpiDTgPIMt0ld8cmuYqlY+EIPjvrmMqZruDhs61hQNAAAAAAEBK9AHAAAAAAAAIgAg6GXadcNj7k4yKUbnVlTLiedXQFXYdCBoNygop/PISNAiAgNt0j7Ae0iA7qlLolruNqLWkPA96J0qgMLK1M7WOGMAfUcwRAIgS6x0i1J1HRzllIPf4WlFY+Dl8kCCLK81TL2djZxTFXMCICJVBKkKNxu1w1mRVor6iFTSVXiJjmWwBXVeJLISvBwAASICArn3tec7n7318rnWqf0dIIwtLtfxo6Zt0HV70UvZYaWvRzBEAiBkVDLgVEwvENnLx+04o7gGpGjFDBwAXTJmf8Yvo35oygIgbuBkHsvPC9jmZcMZ9P+Pwp01yxSaWo+5feyPmd3ai1kBAQVHUiECufe15zufvfXyudap/R0gjC0u1/Gjpm3QdXvRS9lhpa8hA23SPsB7SIDuqUuiWu42otaQ8D3onSqAwsrUztY4YwB9Uq4iBgNt0j7Ae0iA7qlLolruNqLWkPA96J0qgMLK1M7WOGMAfRg7+VpcVAAAgAAAAIAAAACAAAAAAAAAAAAiBgK597XnO5+99fK51qn9HSCMLS7X8aOmbdB1e9FL2WGlrxg0TDZwVAAAgAAAAIAAAACAAAAAAAAAAAABBwABCNoEAEcwRAIgZFQy4FRMLxDZy8ftOKO4BqRoxQwcAF0yZn/GL6N+aMoCIG7gZB7LzwvY5mXDGfT/j8KdNcsUmlqPuX3sj5nd2otZAUcwRAIgS6x0i1J1HRzllIPf4WlFY+Dl8kCCLK81TL2djZxTFXMCICJVBKkKNxu1w1mRVor6iFTSVXiJjmWwBXVeJLISvBwAAUdSIQK597XnO5+99fK51qn9HSCMLS7X8aOmbdB1e9FL2WGlryEDbdI+wHtIgO6pS6Ja7jai1pDwPeidKoDCytTO1jhjAH1SrgABAUdSIQKnHLwN6y9dw9SuBnlo3GoQ7Dtz/KGlTQbbZODJQilyHCECxyoY5j7gkI8ku+2X2jDdrXYDSnH//ue1VxmYc/1Fk5dSriICAqccvA3rL13D1K4GeWjcahDsO3P8oaVNBttk4MlCKXIcGDRMNnBUAACAAAAAgAAAAIABAAAAAwAAACICAscqGOY+4JCPJLvtl9ow3a12A0px//7ntVcZmHP9RZOXGDv5WlxUAACAAAAAgAAAAIABAAAAAwAAAAAA"\n{\n  "txid": "a0b082e3b0579822d4a0b0fa95a4c4662f6b128ffd43fdcfe53c37473ce85dee"\n}\n')])])]),r("h2",{attrs:{id:"conclusion"}},[r("a",{staticClass:"header-anchor",attrs:{href:"#conclusion"}},[e._v("#")]),e._v(" Conclusion")]),e._v(" "),r("p",[e._v("We have built an HDM and we have used it with two indipendent wallets, which\nare compatible with "),r("a",{attrs:{href:"https://en.bitcoin.it/wiki/BIP_0174",target:"_blank",rel:"noopener noreferrer"}},[e._v("BIP 174"),r("OutboundLink")],1),e._v(" and "),r("a",{attrs:{href:"https://bitcoinops.org/en/topics/output-script-descriptors/",target:"_blank",rel:"noopener noreferrer"}},[e._v("Output Descriptors"),r("OutboundLink")],1),e._v(". Hopefully we\nwill see many other compatible wallets beyound "),r("a",{attrs:{href:"https://bitcoincore.org/",target:"_blank",rel:"noopener noreferrer"}},[e._v("Bitcoin Core"),r("OutboundLink")],1),e._v(" and "),r("a",{attrs:{href:"https://bitcoindevkit.org/",target:"_blank",rel:"noopener noreferrer"}},[e._v("BDK"),r("OutboundLink")],1),e._v(",\nwith which we will be able to easily set up multi signature schemes.")])])}),[],!1,null,null,null);t.default=s.exports}}]);