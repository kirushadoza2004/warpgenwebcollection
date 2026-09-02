const crypto = require('crypto');

function generateWgKeyPair() {
    const { privateKey, publicKey } = crypto.generateKeyPairSync('x25519', {
        publicKeyEncoding: { type: 'spki', format: 'der' },
        privateKeyEncoding: { type: 'pkcs8', format: 'der' }
    });
    
    const privBytes = privateKey.subarray(16);
    const pubBytes = publicKey.subarray(12);

    privBytes[0] &= 248;
    privBytes[31] &= 127;
    privBytes[31] |= 64;

    return {
        privateKey: privBytes.toString('base64'),
        publicKey: pubBytes.toString('base64')
    };
}

module.exports = async (req, res) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    if (req.method === 'OPTIONS') {
        return res.status(200).end();
    }

    if (req.method !== 'POST') {
        return res.status(405).json({ error: 'Method Not Allowed' });
    }

    try {
        const keys = generateWgKeyPair();

        const response = await fetch('https://api.cloudflareclient.com/v0a2158/reg', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json; charset=UTF-8',
                'User-Agent': 'okhttp/3.12.1'
            },
            body: JSON.stringify({
                "key": keys.publicKey,
                "install_id": "",
                "fcm_token": "",
                "tos": new Date().toISOString(),
                "model": "PC",
                "type": "Android",
                "locale": "ru_RU"
            })
        });

        const data = await response.json();

        if (!response.ok || !data.success || !data.result) {
            const errorMsg = data.errors && data.errors.length > 0 
                ? data.errors[0].message 
                : `Код ошибки API: ${response.status}`;
            throw new Error(`Cloudflare вернул ошибку: ${errorMsg}`);
        }

        const result = data.result;

        const interfaceObj = result.config?.interface || result.interface;
        const peersObj = result.config?.peers || result.peers;

        if (!interfaceObj || !peersObj || !peersObj[0]) {
            throw new Error('Получен некорректный ответ от WARP API (отсутствуют конфигурационные данные)');
        }

        const clientIPv4 = interfaceObj.addresses?.v4 || "10.0.0.2";
        const clientIPv6 = interfaceObj.addresses?.v6 || "fd01:5ca1:ab1e::2";
        const peerPublicKey = peersObj[0].public_key;

        const endpoint = req.body?.endpoint || "162.159.192.1:2408";
        const dns = req.body?.dns || "1.1.1.1, 1.0.0.1";

        const jc = Math.floor(Math.random() * 8) + 3;
        const jmin = 40;
        const jmax = 70;
        const s1 = Math.floor(Math.random() * 150) + 15;
        const s2 = Math.floor(Math.random() * 150) + 15;
        const h1 = Math.floor(Math.random() * 1000000000) + 1000000;
        const h2 = Math.floor(Math.random() * 1000000000) + 1000000;
        const h3 = Math.floor(Math.random() * 1000000000) + 1000000;
        const h4 = Math.floor(Math.random() * 1000000000) + 1000000;

        const configText = `[Interface]
PrivateKey = ${keys.privateKey}
Address = ${clientIPv4}/32, ${clientIPv6}/128
DNS = ${dns}
Jc = ${jc}
Jmin = ${jmin}
Jmax = ${jmax}
S1 = ${s1}
S2 = ${s2}
H1 = ${h1}
H2 = ${h2}
H3 = ${h3}
H4 = ${h4}

[Peer]
PublicKey = ${peerPublicKey}
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = ${endpoint}
`;

        return res.status(200).json({ success: true, config: configText });

    } catch (error) {
        return res.status(500).json({ success: false, error: error.message });
    }
};
