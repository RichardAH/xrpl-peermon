// Generates tests/vectors_{xahau,xrpl}.json using the official binary codecs:
//   npm install xahau-binary-codec ripple-binary-codec
//   node tests/gen_vectors.js
// Each vector is {name, hex, expected}, where expected = codec.decode(hex).
// The vectors are committed, so running the tests only needs python3.

const fs = require('fs')
const path = require('path')
const xahau = require('xahau-binary-codec')
const xrpl = require('ripple-binary-codec')

const A1 = 'rf1BiGeXwwQoi8Z2ueFYTEXSwuJYfV2Jpn'
const A2 = 'ra5nK24KXen9AHvsdFTKHSANinZseWnPcX'
const A3 = 'rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh'
const H = (b, n) => b.repeat(n)
const H32 = (b) => H(b, 64)
const PUB = '03AB40A0490F9B7ED8DF29D246BF2D6269820A0EE7742ACDD457BEA7C7D0931EDB'
const SIG = '30440220' + H32('1A') + '0220' + H32('2B')
const common = (o) => ({ Fee: '12', Sequence: 7, SigningPubKey: PUB, TxnSignature: SIG, Account: A1, ...o })
const wasm = (n) => Array.from({ length: n }, (_, i) => (i % 256).toString(16).padStart(2, '0')).join('').toUpperCase()

const xahauTx = {
  'Payment XAH with memo': common({
    TransactionType: 'Payment', NetworkID: 21337, Destination: A2, Amount: '1000000', DestinationTag: 42,
    LastLedgerSequence: 12345678, Flags: 0,
    Memos: [{ Memo: { MemoType: '74657374', MemoData: 'DEADBEEF' } }],
  }),
  'SetHook (14KB code -> 3 byte VL, params, grants)': common({
    TransactionType: 'SetHook', NetworkID: 21337, Flags: 0,
    Hooks: [
      { Hook: {
        CreateCode: wasm(14000), HookOn: H32('F'), HookNamespace: H32('A'), HookApiVersion: 0, Flags: 1,
        HookParameters: [{ HookParameter: { HookParameterName: '414D54', HookParameterValue: '0102030405' } }],
        HookGrants: [{ HookGrant: { HookHash: H32('C'), Authorize: A3 } }],
      } },
      { Hook: {} },
      { Hook: { HookHash: H32('B') } },
    ],
  }),
  'Invoke with blob and params': common({
    TransactionType: 'Invoke', NetworkID: 21337, Destination: A2, Blob: 'CAFEBABE',
    HookParameters: [{ HookParameter: { HookParameterName: '4F50', HookParameterValue: '01' } }],
  }),
  'URITokenMint': common({
    TransactionType: 'URITokenMint', NetworkID: 21337, URI: '697066733A2F2F62616679', Digest: H32('D'), Flags: 1,
  }),
  'URITokenBuy with fractional IOU': common({
    TransactionType: 'URITokenBuy', NetworkID: 21337, URITokenID: H32('E'),
    Amount: { currency: 'USD', issuer: A3, value: '1234.5678' },
  }),
  'Remit (amounts, uritokenids, mint, inform)': common({
    TransactionType: 'Remit', NetworkID: 21337, Destination: A2, Inform: A3, Blob: '00FF',
    Amounts: [
      { AmountEntry: { Amount: '5' } },
      { AmountEntry: { Amount: { currency: 'EUR', issuer: A3, value: '0.000001' } } },
      { AmountEntry: { Amount: { currency: '0158415500000000C1F76FF6ECB0BAC600000000', issuer: A3, value: '1e20' } } },
    ],
    URITokenIDs: [H32('1'), H32('2')],
    MintURIToken: { URI: '68747470733A2F2F', Digest: H32('3'), Flags: 1 },
  }),
  'Import (blob)': common({ TransactionType: 'Import', NetworkID: 21337, Blob: '7B22223A307D', Issuer: A3 }),
  'ClaimReward': common({ TransactionType: 'ClaimReward', NetworkID: 21337, Issuer: A3, Flags: 0 }),
  'GenesisMint': common({
    TransactionType: 'GenesisMint', NetworkID: 21337,
    GenesisMints: [{ GenesisMint: { Destination: A2, Amount: '100000000' } }],
  }),
  'SetRemarks (ObjectID collides with XRPL AMMID)': common({
    TransactionType: 'SetRemarks', NetworkID: 21337, ObjectID: H32('9'),
    Remarks: [{ Remark: { RemarkName: '6E616D65', RemarkValue: '76616C', Flags: 1 } }],
  }),
  'CronSet': common({ TransactionType: 'CronSet', NetworkID: 21337, StartTime: 800000000, RepeatCount: 3, DelaySeconds: 3600 }),
  'EscrowFinish with EscrowID (collides with XRPL VaultID)': common({
    TransactionType: 'EscrowFinish', NetworkID: 21337, Owner: A2, OfferSequence: 5, EscrowID: H32('7'),
  }),
  'AccountSet with TickSize (3 byte field header)': common({
    TransactionType: 'AccountSet', NetworkID: 21337, TickSize: 5, SetFlag: 8, TransferRate: 1005000000,
  }),
  'Payment with paths and SendMax': common({
    TransactionType: 'Payment', NetworkID: 21337, Destination: A2,
    Amount: { currency: 'USD', issuer: A3, value: '10' },
    SendMax: '20000000',
    Paths: [[{ currency: 'USD', issuer: A3 }], [{ account: A2 }, { currency: 'XAH' }, { currency: 'EUR', issuer: A3 }]],
    Flags: 131072,
  }),
}

const xahauValidation = {
  'Validation (flag ledger fee/amendment votes)': {
    Flags: 2147483649, LedgerSequence: 12345, CloseTime: 800000000, SigningTime: 800000001, LoadFee: 256,
    Cookie: 'A1B2C3D4E5F60718', ServerVersion: '1A0B000000000001',
    LedgerHash: H32('4'), ConsensusHash: H32('5'), ValidatedHash: H32('6'),
    Amendments: [H32('7'), H32('8')],
    BaseFeeDrops: '10', ReserveBaseDrops: '1000000', ReserveIncrementDrops: '200000',
    SigningPubKey: PUB, Signature: SIG,
  },
}

const xrplTx = {
  'Payment with paths, SendMax, DeliverMin': common({
    TransactionType: 'Payment', Destination: A2, Amount: { currency: 'USD', issuer: A3, value: '25.5' },
    SendMax: { currency: 'EUR', issuer: A3, value: '30' }, DeliverMin: { currency: 'USD', issuer: A3, value: '25' },
    Paths: [[{ currency: 'XRP' }, { currency: 'USD', issuer: A3 }], [{ account: A2 }]], Flags: 131072,
  }),
  'MPT Payment': common({
    TransactionType: 'Payment', Destination: A2,
    Amount: { mpt_issuance_id: '00000004A407AF5856CCF3C42619DAA925813FC955C72983', value: '100' },
  }),
  'AMMDeposit (Issue XRP + IOU, AMM fields)': common({
    TransactionType: 'AMMDeposit', Asset: { currency: 'XRP' }, Asset2: { currency: 'USD', issuer: A3 },
    Amount: '1000', EPrice: { currency: 'USD', issuer: A3, value: '0.5' }, Flags: 0x00080000,
  }),
  'XChainCommit (XChainBridge, UInt64)': common({
    TransactionType: 'XChainCommit', Amount: '10000', XChainClaimID: '13F',
    XChainBridge: { LockingChainDoor: A2, LockingChainIssue: { currency: 'XRP' },
                    IssuingChainDoor: A3, IssuingChainIssue: { currency: 'USD', issuer: A1 } },
  }),
  'VaultCreate (MPT Issue, Number)': common({
    TransactionType: 'VaultCreate', Asset: { mpt_issuance_id: '00000004A407AF5856CCF3C42619DAA925813FC955C72983' },
    AssetsMaximum: '123456.789',
  }),
  'OracleSet (Currency type, UInt8 scale, UInt64)': common({
    TransactionType: 'OracleSet', OracleDocumentID: 1, LastUpdateTime: 1700000000, Provider: '70726F76', AssetClass: '63757272',
    PriceDataSeries: [{ PriceData: { BaseAsset: 'XRP', QuoteAsset: 'USD', AssetPrice: '74', Scale: 2 } }],
  }),
  'AMMClawback (AMMID-era fields)': common({
    TransactionType: 'AMMClawback', Holder: A2, Asset: { currency: 'USD', issuer: A1 }, Asset2: { currency: 'XRP' },
  }),
}

const xrplValidation = {
  'Validation with NetworkID': {
    Flags: 2147483649, LedgerSequence: 99999, SigningTime: 800000001, Cookie: 'FFEEDDCCBBAA9988',
    LedgerHash: H32('4'), ConsensusHash: H32('5'), ValidatedHash: H32('6'), SigningPubKey: PUB, Signature: SIG,
    NetworkID: 1,
  },
}

function build(codec, set) {
  const out = []
  for (const [name, obj] of Object.entries(set)) {
    const hex = codec.encode(obj)
    out.push({ name, hex, expected: codec.decode(hex) })
  }
  return out
}

const dir = __dirname
fs.writeFileSync(path.join(dir, 'vectors_xahau.json'),
  JSON.stringify(build(xahau, { ...xahauTx, ...xahauValidation }), null, 1))
fs.writeFileSync(path.join(dir, 'vectors_xrpl.json'),
  JSON.stringify(build(xrpl, { ...xrplTx, ...xrplValidation }), null, 1))
console.log('ok')
