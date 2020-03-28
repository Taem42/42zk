mod lib;

use bellman::{
    gadgets::{
        boolean::{AllocatedBit, Boolean},
        multipack,
        sha256::sha256,
    },
    groth16, Circuit, ConstraintSystem, SynthesisError,
};
use pairing::bls12_381::Bls12;
use pairing::Engine;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};

fn combine(amount: u128, nonce: u128) -> [u8; 32] {
    let amount_bytes = amount.to_be_bytes();
    let nonce_bytes = nonce.to_be_bytes();

    let mut bytes = [0u8; 32];
    for i in 0..16 {
        bytes[i] = amount_bytes[i];
        bytes[i + 16] = nonce_bytes[i];
    }

    bytes
}

fn main() {
    let mut input_amount = 0;
    let mut input_nonce = 0;
    let mut output_amount = 0;
    let mut output_nonce = 0;
    let mut verifying_key: String = String::new();
    let mut input_hash: String = String::new();
    let mut output_hash: String = String::new();
    let mut proof: String = String::new();

    {
        let mut ap = argparse::ArgumentParser::new();
        ap.refer(&mut input_amount).add_option(&["--input_amount"], argparse::Store, "");
        ap.refer(&mut input_nonce).add_option(&["--input_nonce"], argparse::Store, "");
        ap.refer(&mut output_amount).add_option(&["--output_amount"], argparse::Store, "");
        ap.refer(&mut output_nonce).add_option(&["--output_nonce"], argparse::Store, "");
        ap.refer(&mut verifying_key).add_option(&["--verifying_key"], argparse::Store, "");
        ap.refer(&mut input_hash).add_option(&["--input_hash"], argparse::Store, "");
        ap.refer(&mut output_hash).add_option(&["--output_hash"], argparse::Store, "");
        ap.refer(&mut proof).add_option(&["--proof"], argparse::Store, "");
        ap.parse_args_or_exit();
    }

    if input_amount != 0 {
        let params = lib::trust_setup();
        let witness = lib::Witness {
            input_amount: input_amount,
            input_nonce: input_nonce,
            output_amount: output_amount,
            output_nonce: output_nonce,
        };
        let proof = lib::generate_proof(witness, &params.to_bytes());
        let input_hash = Sha256::digest(&combine(2, 10)).to_vec();
        let output_hash = Sha256::digest(&combine(2, 20)).to_vec();

        println!("verifying_key: {:?}", hex::encode(params.verifying_key()));
        println!("input hash   : {:?}", hex::encode(input_hash));
        println!("output hash  : {:?}", hex::encode(output_hash));
        println!("proof        : {:?}", hex::encode(proof.to_bytes()));
    } else {
        let input = lib::Input {
            from_hash: hex::decode(input_hash).unwrap(),
            to_hash: hex::decode(output_hash).unwrap(),
        };

        if lib::verify(&hex::decode(verifying_key).unwrap(), &hex::decode(proof).unwrap(), input) {
            println!("verified")
        } else {
            println!("verify failed")
        }
    }

    //     let input_hash = Sha256::digest(&combine(2, 10)).to_vec();
    //     let output_hash = Sha256::digest(&combine(2, 20)).to_vec();
    //     let input = Input {
    //         from_hash: input_hash,
    //         to_hash: output_hash,
    //     };
}

// verifying_key: "06ddf6aa37ae43f6ddb79497580f43718626f29e80f6866292244f662dd9a5ce0b28c6b354b40d89de386598b4e554b2025f66ddb92a1d96668b75ad74e6fee96e171648a535450b6e3e5ea8c10044c5f9cfe6bfb76ee06a5d3e461e6d06f1c20984513ab2438059f8c33b33c05a3c9a6833d7dfb2692bde1037b4a112ddfda708023ab2387c57c923501be47b871cce1759dc1402456f2ed568bf32804c1556721bd8933cc7dc3636621511217be678da76bd566a2ca22e245d3c1ebb8c36e20a89bf1577d7039e2c78bce8452f1e15fef9e37e2ee410afd98e2cd847b06a167909dc52e363ee3af036ff7c8982646a18ae3f6d1d9cbc9ac7d1c3ae209f937096072088344a382e4319bb92d90b588b25eefd3428005bf97174fec608b8d10115b3bd3ac31e3e81d9f0449f9acc20f2f97f2475555620d2c8adcda7438f33f10cfaca14ec04a6a2d7781cbb12cceec8115dd5c77025942ebf51712134e079d6e47201bbec11296383d16d5adf1fc2a278ec272222aefc7b072ad2acae2c8a6e0838671c5ec25fb47c6f100e9c10ee37491b07daf9bc3df6567c09c44a7e749bf7d6332cd93e9f6645a71752e1102b210e7c86f5a25855c4d5a63bbb1985e741b3b4ee05f817393fc8c3fb82438c3398c545b551e9e4385515b55b624edb628500ce51ca81015b86bc07906298981fa58a5ad3486356aabbf4b633b89dcc5b75618815d5b94344e26fa895f8ff4d13b4074512fa43171288127b177217e19e8dd18d1203c32f4b5b6d3bbeab95b9a561945fae04cb336e884fd23006b418debe09d99ef80705c71881806e2a0c9e20bfe757c4d3472a6c27b21f0ea54c94f1dce5b242a11abab234c141dc5e4da2ab1f068f88903be1afd7dc37e6bba7585cf1dfe6750b975a9518d5bcbf4c204f9508137fc3ff871db9a4a7124ce6bdeec99711a8bd99fe48064cee01d971ae6376d659c858d51347c2d027bf53e25fad8739b392543fe0f191b0d740f3431205b8551348902440972c05c4120bdd9fd2f9a8470289b14cad7108cc11e1b508ee7730a57a163b88e45535e029cd8fc2df4398196b5d8019ff4896ad438a5bc93a63e3b267fd6d72600ccec47441c02131d3bcdb670c9e26de662d4f3d7285bf1278e8150dff89b95e6a414769a43389bdb169bac438e6e116fe26d2671cf0a89afce34d0c7282ed6cdd2342cfb6b24b2e4a0b0000000401aa8d728448bbb39e2ec05aca385ff0389513134e17820ab8e5486ec21b8406a2cd125c3858dc2f859634b3836a4c081090cee22d591e8ab29b3d1a6187380b3c73c60795bf6f85147fef6ee6b8d28540796bbd635388c1d6fa8e322640c6790c4b8a37f25745a8885c80085fa9a8e4e24ef1ef2355a205052e14d4eb30f04b342e9feba868432509405f7ade1579d50995693721895047d8088048e17d7de14839a65327cfbed09b8f267c4dbec4826b9426620a41115daf84038076153b8e0c1c81c7cbc7aff2727cf9db22912704e24649ad73f4b95461ff015acdfada4289b2a3813bce4e0b497d928330927c6406804ed350ebdd86bf035c64da0db1e8acbe230d114c3fdd59c715040adf3f0f48e67143ca248d53b7f4dfa49668ecf204652cf4f489f990c73c872f7a95b67e6f548304822f49d09d039a1c4fc7ed7a8fb1d378d23a38155e055b17654fc499051892244b4ff7738fe15ff63e3a8353b3f4ef5a857da96d19fbaea7b3a8c307612946359a847557c94b2397e5b12970"
// input hash   : "963eb2f10c14bbe6cfb316aa96601ea01f77ab5c15c6110c99017a01981583ce"
// output hash  : "a1dd8fab71bb7f07b7022c17bc5a0aa22d767b2c9d28fc6e8869b666f46a0b4e"
// proof        : "871d7ee36017cefb6aa487ba46aac17cbae76510b691e548e02b27df16db87a2b7a93f594434bf254629e9ec50a91c2da8af27d890addb11dca2c3d4f5b6c4bd77d2dcb3db719523a5fbd54e97dd1fe4fa0d63e5727c427f6697c7c901a6cff610567892e682fa54358829c05d6b065a4240ffdc9b5a9f4e0281233d0775165969b0eb613c2ea2536bf80b1b00dcce3d81a1dde032a399536763aef74924dd30484a03bc956e6223ea9cb032dfe1b75e306cf3d0052ce5de869b9b13b11e1fd5"
