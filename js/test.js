const PRE = require('bm-pre');
// const params = PRE.init({
// 	g: "The generator for G1",
// 	h: "The generator for G2",
// 	returnHex: true
// })

async function init() {
	await PRE.init({
		g: "The generator for G1",
		h: "The generator for G2",
		returnHex: true
	})
}

init()
// const params = { 
// 	g:
//    '231793c6816599f811f84cdf0a6f4b148d0127356a431c75515ac0db95e08dba99724c654767bfa7730ccb49e52a0b03',
//   h:
//    '79b6cc5cc3986ba53952e538750077cec8bcff23def03524f7e47229a64e27dd0e062a86a5381e716f3725b6632ce1196e449ad2c789574fc7e23d3a56a10be06994fd0530f0a5db0555dcd1a7d4e0b1501dd13f3097cd5bd85b2eab3d9e830b' 
// }
function genKeyInG1() {
	return PRE.keyGenInG1(params, {
		returnHex: true
	})
}

function genKeyInG2() {
	return PRE.keyGenInG2(params, {
		returnHex: true
	})
}

PRE.init({
	g: "The generator for G1",
	h: "The generator for G2",
	returnHex: true
}).then(params => {
	console.log(params)
	// const plain = PRE.randomGen();
	const plain = Array(64).fill('3').join('')

	const A = genKeyInG1()
	const B = PRE.keyGenInG2(params, {
		returnHex: true
	});

	const encrypted = PRE.enc(plain, A.pk, params, {
		returnHex: true
	});
	const decrypted = PRE.dec(encrypted, A.sk, params);

	const reKey = PRE.rekeyGen(A.sk, B.pk, {
		returnHex: true
	});

	const reEncypted = PRE.reEnc(encrypted, reKey, {
		returnHex: true
	});
	const reDecrypted = PRE.reDec(reEncypted, B.sk);

	const crypto = require('crypto');
	const msg = "1111";
	const hash = crypto.createHash('sha256');
	hash.update(msg);
	const msgHash = hash.digest('hex');

	const sig = PRE.sign(msgHash, A.sk);
	const C = PRE.keyGenInG1(params, {
		returnHex: false
	});

	console.log("plain\n", plain);
	console.log("A's key pair\n", A);
	console.log("B's key pair\n", B);
	console.log("encrypted\n", encrypted);
	console.log("decrypted\n", decrypted);
	console.log("reKey\n", reKey);
	console.log("reEncypted\n", reEncypted);
	console.log("reDecrypted\n", reDecrypted);
	console.log("plain==decrypted==reDecrypted:", plain === decrypted && plain === reDecrypted);
	console.log("A's signature", sig);
	console.log("verify A's signature by A's pk:", PRE.verify(msgHash, sig, A.pk, params));
	console.log("verify A's signature by C's pk:", PRE.verify(msgHash, sig, C.pk, params))

}).catch(err => {
	console.log(err)
});