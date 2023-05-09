const express = require('express');
const nearAPI = require('near-api-js');
const nacl = require('tweetnacl');

// Replace these values with your network configuration
const networkId = 'testnet';
const nodeUrl = 'https://rpc.testnet.near.org';
const walletUrl = 'https://wallet.testnet.near.org';
const helperUrl = 'https://helper.testnet.near.org';

const config = {
  networkId: networkId,
  nodeUrl: nodeUrl,
  walletUrl: walletUrl,
  helperUrl: helperUrl
};

const app = express();
app.use(express.json()); // for parsing JSON request bodies

// Endpoint for encrypting data
app.post('/encrypt', async (req, res) => {
  const { data, publicKey } = req.body;
  const nonce = nacl.randomBytes(nacl.box.nonceLength);
  const encryptedData = nacl.box(
    Buffer.from(data, 'utf8'),
    nonce,
    Buffer.from(publicKey, 'hex'), // assuming publicKey is a hexadecimal string
    nearAPI.utils.KeyPair.fromRandom('ed25519').secretKey // generate a temporary private key for encryption
  );
  res.json({ encryptedData: Buffer.from(encryptedData).toString('hex'), nonce: Buffer.from(nonce).toString('hex') });
});

// Endpoint for decrypting data
app.post('/decrypt', async (req, res) => {
  const { encryptedData, nonce, privateKey } = req.body;
  const decryptedData = nacl.box.open(
    Buffer.from(encryptedData, 'hex'),
    Buffer.from(nonce, 'hex'),
    Buffer.from(nearAPI.utils.PublicKey.fromSecretKey(Buffer.from(privateKey, 'hex')).data, 'hex'), // derive public key from private key
    Buffer.from(privateKey, 'hex')
  );
  res.json({ decryptedData: Buffer.from(decryptedData).toString('utf8') });
});

const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`Server listening on port ${port}`);
});

async function createNearAccount(accountId, keyPair) {
  const masterAccount = await nearAPI.AccountConnection.connect(config);
  const publicKey = keyPair.getPublicKey();
  await masterAccount.createAccount(accountId, publicKey, 0.5, publicKey.toString());
  return publicKey.toString();
}

app.post('/create-account', async (req, res) => {
  const { accountId, passphrase } = req.body;

  try {
    const keyPair = nearAPI.utils.KeyPair.fromRandom('ed25519');
    const publicKey = await createNearAccount(accountId, keyPair);
    const encryptedPrivateKey = nacl.secretbox(
      keyPair.secretKey,
      Buffer.from(passphrase, 'utf8')
    );

    res.json({
      accountId,
      publicKey,
      encryptedPrivateKey: Buffer.from(encryptedPrivateKey).toString('hex'),
    });
  } catch (error) {
    console.error('Failed to create account:', error);
    res.status(500).send('Failed to create account');
  }
});

const accounts = {};

app.post('/store-keys', (req, res) => {
  const { accountId, publicKey, encryptedPrivateKey } = req.body;

  accounts[accountId] = {
    publicKey,
    encryptedPrivateKey,
  };

  res.status(200).send('Keys stored successfully');
});

app.get('/keys/:accountId', (req, res) => {
  const accountId = req.params.accountId;

  if (accounts[accountId]) {
    res.json(accounts[accountId]);
  } else {
    res.status(404).send('Account not found');
  }
});


