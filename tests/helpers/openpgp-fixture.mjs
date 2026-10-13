// Test-only OpenPGP v4 fixture encoder. Private keys are generated in memory,
// never saved; production verification uses GnuPG, never this implementation.
// This keeps integration tests runnable when gpg-agent sockets are unavailable.
import {generateKeyPairSync, createHash, sign} from 'node:crypto';

const bytes = (...values) => Buffer.concat(values.map(value => Buffer.isBuffer(value) ? value : Buffer.from(value)));
const u16 = value => {const out = Buffer.alloc(2);out.writeUInt16BE(value);return out;};
const u32 = value => {const out = Buffer.alloc(4);out.writeUInt32BE(value);return out;};
const sha = (algorithm,value) => createHash(algorithm).update(value).digest();
function mpi(input) {
  const first = input.findIndex(value => value !== 0), data = first < 0 ? Buffer.alloc(0) : input.subarray(first);
  return bytes(u16(data.length ? (data.length-1)*8 + 32-Math.clz32(data[0]) : 0),data);
}
function length(size) {
  if (size < 192) return Buffer.from([size]);
  if (size <= 8383) return Buffer.from([((size-192)>>8)+192,(size-192)&255]);
  return bytes([255],u32(size));
}
const packet = (type,body) => bytes([0xc0|type],length(body.length),body);
const subpacket = (type,body) => bytes(length(body.length+1),[type],body);
const keyPrefix = body => bytes([0x99],u16(body.length),body);
function armor(type,data) {
  let crc = 0xb704ce;
  for (const byte of data) {crc ^= byte<<16;for(let bit=0;bit<8;bit++) {crc <<= 1;if(crc&0x1000000) crc ^= 0x1864cfb;}}
  const checksum = Buffer.from([(crc>>16)&255,(crc>>8)&255,crc&255]).toString('base64');
  return `-----BEGIN PGP ${type}-----\n\n${data.toString('base64').match(/.{1,64}/g).join('\n')}\n=${checksum}\n-----END PGP ${type}-----\n`;
}
function key(created) {
  const {publicKey,privateKey} = generateKeyPairSync('rsa',{modulusLength:2048});
  const jwk = publicKey.export({format:'jwk'});
  const body = bytes([4],u32(created),[1],mpi(Buffer.from(jwk.n,'base64url')),mpi(Buffer.from(jwk.e,'base64url')));
  return {body,privateKey,fingerprint:sha('sha1',keyPrefix(body)),created};
}
function signature(signer,type,data,{created = signer.created,extra = []} = {}) {
  const hashed = bytes(subpacket(2,u32(created)),subpacket(33,bytes([4],signer.fingerprint)),...extra);
  const head = bytes([4,type,1,8],u16(hashed.length),hashed);
  const toSign = bytes(data,head,[4,255],u32(head.length));
  const unhashed = subpacket(16,signer.fingerprint.subarray(-8));
  return bytes(head,u16(unhashed.length),unhashed,sha('sha256',toSign).subarray(0,2),mpi(sign('RSA-SHA256',toSign,signer.privateKey)));
}

export function openPgpFixture({subkey = false,subkeys = subkey ? 1 : 0,expired = false,revoked = false} = {}) {
  if (!Number.isInteger(subkeys) || subkeys < 0 || subkeys > 4) throw Error('Fixture supports zero through four signing subkeys.');
  const now = Math.floor(Date.now()/1000), created = now - (expired ? 5*86400 : 60);
  const primary = key(created);
  const uid = Buffer.from('Ephemeral security fixture <fixture@example.invalid>');
  const certification = signature(primary,0x13,bytes(keyPrefix(primary.body),[0xb4],u32(uid.length),uid),{
    extra:[subpacket(27,[subkeys ? 1 : 3]),...(expired ? [subpacket(9,u32(86400))] : [])],
  });
  const revocation = revoked ? packet(2,signature(primary,0x20,keyPrefix(primary.body),{created:created+10})) : Buffer.alloc(0);
  let publicPackets = bytes(packet(6,primary.body),revocation,packet(13,uid),packet(2,certification));
  const signers = [];
  for (let index = 0; index < subkeys; index++) {
    const signingKey = key(created);signers.push(signingKey);
    const bound = bytes(keyPrefix(primary.body),keyPrefix(signingKey.body));
    const crossCertification = signature(signingKey,0x19,bound);
    const binding = signature(primary,0x18,bound,{extra:[subpacket(27,[2]),subpacket(32,crossCertification)]});
    publicPackets = bytes(publicPackets,packet(14,signingKey.body),packet(2,binding));
  }
  if (!signers.length) signers.push(primary);
  const signData = (signer,data) => armor('SIGNATURE',packet(2,signature(signer,0x00,Buffer.from(data),{created:created+5})));
  return {
    primaryFingerprint:primary.fingerprint.toString('hex').toUpperCase(),
    signerFingerprint:signers[0].fingerprint.toString('hex').toUpperCase(),
    signerFingerprints:signers.map(signer=>signer.fingerprint.toString('hex').toUpperCase()),
    publicKey:armor('PUBLIC KEY BLOCK',publicPackets),
    // Sign in the key's valid past lifetime, so verification must notice expiry
    // or revocation now rather than merely reject an impossible creation date.
    sign:(data,index = 0) => {if(!signers[index]) throw Error('Unknown fixture signer.');return signData(signers[index],data);},
    // Deliberately valid text-mode signature for exact-byte policy rejection tests.
    signText:(data,index = 0) => {if(!signers[index]) throw Error('Unknown fixture signer.');return armor('SIGNATURE',packet(2,signature(signers[index],0x01,Buffer.from(String(data).replace(/\r?\n/g,'\r\n')),{created:created+5})));},
    signWithPrimary:data => signData(primary,data),
  };
}
