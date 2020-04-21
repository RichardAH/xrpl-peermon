inline const char* txlookup_type_name(int tx_type) {
	switch(tx_type) {

		case -393: {
			return "telNO_DST_PARTIAL";
		}
		case -281: {
			return "temBAD_SRC_ACCOUNT";
		}
		case -189: {
			return "tefPAST_SEQ";
		}
		case -96: {
			return "terNO_ACCOUNT";
		}
		case -275: {
			return "temREDUNDANT";
		}
		case -194: {
			return "tefCREATED";
		}
		case -279: {
			return "temDST_IS_SRC";
		}
		case -99: {
			return "terRETRY";
		}
		case -276: {
			return "temINVALID_FLAG";
		}
		case -288: {
			return "temBAD_SEND_XRP_LIMIT";
		}
		case -94: {
			return "terNO_LINE";
		}
		case -196: {
			return "tefBAD_AUTH";
		}
		case -295: {
			return "temBAD_EXPIRATION";
		}
		case -286: {
			return "temBAD_SEND_XRP_NO_DIRECT";
		}
		case -284: {
			return "temBAD_SEND_XRP_PATHS";
		}
		case -195: {
			return "tefBAD_LEDGER";
		}
		case -190: {
			return "tefNO_AUTH_REQUIRED";
		}
		case -93: {
			return "terOWNERS";
		}
		case -91: {
			return "terLAST";
		}
		case -90: {
			return "terNO_RIPPLE";
		}
		case -294: {
			return "temBAD_FEE";
		}
		case -92: {
			return "terPRE_SEQ";
		}
		case -187: {
			return "tefMASTER_DISABLED";
		}
		case -296: {
			return "temBAD_CURRENCY";
		}
		case -193: {
			return "tefDST_TAG_NEEDED";
		}
		case -282: {
			return "temBAD_SIGNATURE";
		}
		case -199: {
			return "tefFAILURE";
		}
		case -397: {
			return "telBAD_PATH_COUNT";
		}
		case -280: {
			return "temBAD_TRANSFER_RATE";
		}
		case -188: {
			return "tefWRONG_PRIOR";
		}
		case -398: {
			return "telBAD_DOMAIN";
		}
		case -298: {
			return "temBAD_AMOUNT";
		}
		case -297: {
			return "temBAD_AUTH_MASTER";
		}
		case -292: {
			return "temBAD_LIMIT";
		}
		case -293: {
			return "temBAD_ISSUER";
		}
		case -396: {
			return "telBAD_PUBLIC_KEY";
		}
		case -197: {
			return "tefBAD_ADD_AUTH";
		}
		case -291: {
			return "temBAD_OFFER";
		}
		case -285: {
			return "temBAD_SEND_XRP_PARTIAL";
		}
		case -278: {
			return "temDST_NEEDED";
		}
		case -198: {
			return "tefALREADY";
		}
		case -272: {
			return "temUNCERTAIN";
		}
		case -399: {
			return "telLOCAL_ERROR";
		}
		case -274: {
			return "temREDUNDANT_SEND_MAX";
		}
		case -191: {
			return "tefINTERNAL";
		}
		case -289: {
			return "temBAD_PATH_LOOP";
		}
		case -192: {
			return "tefEXCEPTION";
		}
		case -273: {
			return "temRIPPLE_EMPTY";
		}
		case -394: {
			return "telINSUF_FEE_P";
		}
		case -283: {
			return "temBAD_SEQUENCE";
		}
		case -186: {
			return "tefMAX_LEDGER";
		}
		case -98: {
			return "terFUNDS_SPENT";
		}
		case -287: {
			return "temBAD_SEND_XRP_MAX";
		}
		case -395: {
			return "telFAILED_PROCESSING";
		}
		case -97: {
			return "terINSUF_FEE_B";
		}
		case 0: {
			return "tesSUCCESS";
		}
		case -290: {
			return "temBAD_PATH";
		}
		case -299: {
			return "temMALFORMED";
		}
		case -271: {
			return "temUNKNOWN";
		}
		case -277: {
			return "temINVALID";
		}
		case -95: {
			return "terNO_AUTH";
		}
		case -270: {
			return "temBAD_TICK_SIZE";
		}
		case 100: {
			return "tecCLAIM";
		}
		case 101: {
			return "tecPATH_PARTIAL";
		}
		case 102: {
			return "tecUNFUNDED_ADD";
		}
		case 103: {
			return "tecUNFUNDED_OFFER";
		}
		case 104: {
			return "tecUNFUNDED_PAYMENT";
		}
		case 105: {
			return "tecFAILED_PROCESSING";
		}
		case 121: {
			return "tecDIR_FULL";
		}
		case 122: {
			return "tecINSUF_RESERVE_LINE";
		}
		case 123: {
			return "tecINSUF_RESERVE_OFFER";
		}
		case 124: {
			return "tecNO_DST";
		}
		case 125: {
			return "tecNO_DST_INSUF_XRP";
		}
		case 126: {
			return "tecNO_LINE_INSUF_RESERVE";
		}
		case 127: {
			return "tecNO_LINE_REDUNDANT";
		}
		case 128: {
			return "tecPATH_DRY";
		}
		case 129: {
			return "tecUNFUNDED";
		}
		case 130: {
			return "tecNO_ALTERNATIVE_KEY";
		}
		case 131: {
			return "tecNO_REGULAR_KEY";
		}
		case 132: {
			return "tecOWNERS";
		}
		case 133: {
			return "tecNO_ISSUER";
		}
		case 134: {
			return "tecNO_AUTH";
		}
		case 135: {
			return "tecNO_LINE";
		}
		case 136: {
			return "tecINSUFF_FEE";
		}
		case 137: {
			return "tecFROZEN";
		}
		case 138: {
			return "tecNO_TARGET";
		}
		case 139: {
			return "tecNO_PERMISSION";
		}
		case 140: {
			return "tecNO_ENTRY";
		}
		case 141: {
			return "tecINSUFFICIENT_RESERVE";
		}
		case 142: {
			return "tecNEED_MASTER_KEY";
		}
		case 143: {
			return "tecDST_TAG_NEEDED";
		}
		case 144: {
			return "tecINTERNAL";
		}
		case 145: {
			return "tecOVERSIZE";
		}
		case 146: {
			return "tecCRYPTOCONDITION_ERROR";
		}
		case 147: {
			return "tecINVARIANT_FAILED";
		}
		case 148: {
			return "tecEXPIRED";
		}
		case 149: {
			return "tecDUPLICATE";
		}
		default: {
			return "UNKNOWN_TX_TYPE";
		}
	}
}
inline const char* lelookup_type_name(int le_type) {
	switch(le_type) {

		case -3: {
			return "Any";
		}
		case -2: {
			return "Child";
		}
		case -1: {
			return "Invalid";
		}
		case 97: {
			return "AccountRoot";
		}
		case 100: {
			return "DirectoryNode";
		}
		case 114: {
			return "RippleState";
		}
		case 84: {
			return "Ticket";
		}
		case 83: {
			return "SignerList";
		}
		case 111: {
			return "Offer";
		}
		case 104: {
			return "LedgerHashes";
		}
		case 102: {
			return "Amendments";
		}
		case 115: {
			return "FeeSettings";
		}
		case 117: {
			return "Escrow";
		}
		case 120: {
			return "PayChannel";
		}
		case 112: {
			return "DepositPreauth";
		}
		case 67: {
			return "Check";
		}
		case 110: {
			return "Nickname";
		}
		case 99: {
			return "Contract";
		}
		case 103: {
			return "GeneratorMap";
		}
		default: {
			return "UNKNOWN_LE_TYPE";
		}
	}
}
inline const char* stlookup_type_name(int st_type) {
	switch(st_type) {
		case 10003: {
			return "Validation";
		}
		case -1: {
			return "Done";
		}
		case 4: {
			return "Hash128";
		}
		case 7: {
			return "Blob";
		}
		case 8: {
			return "AccountID";
		}
		case 6: {
			return "Amount";
		}
		case 5: {
			return "Hash256";
		}
		case 16: {
			return "UInt8";
		}
		case 19: {
			return "Vector256";
		}
		case 14: {
			return "STObject";
		}
		case -2: {
			return "Unknown";
		}
		case 10001: {
			return "Transaction";
		}
		case 17: {
			return "Hash160";
		}
		case 18: {
			return "PathSet";
		}
		case 10002: {
			return "LedgerEntry";
		}
		case 1: {
			return "UInt16";
		}
		case 0: {
			return "NotPresent";
		}
		case 3: {
			return "UInt64";
		}
		case 2: {
			return "UInt32";
		}
		case 15: {
			return "STArray";
		}
		default: {
			return "UNKNOWN_ST_TYPE";
		}
	}
}
inline int stlookup_type_size(int st_type) {
	switch(st_type) {
		case 10003: {
			return 0;
		}
		case -1: {
			return 0;
		}
		case 4: {
			return 16;
		}
		case 7: {
			return 0;
		}
		case 8: {
			return 0;
		}
		case 6: {
			return 0;
		}
		case 5: {
			return 32;
		}
		case 16: {
			return 1;
		}
		case 19: {
			return 32;
		}
		case 14: {
			return 0;
		}
		case -2: {
			return 0;
		}
		case 10001: {
			return 0;
		}
		case 17: {
			return 20;
		}
		case 18: {
			return 0;
		}
		case 10002: {
			return 0;
		}
		case 1: {
			return 2;
		}
		case 0: {
			return 0;
		}
		case 3: {
			return 8;
		}
		case 2: {
			return 4;
		}
		case 15: {
			return 0;
		}
		default: {
			return -1;
		}
	}
}
inline const char* stlookup_field_name(int st_type, int field_type) {
	switch(st_type) {
		case 10003: {
			switch(field_type) {
				case 1: {
					return "Validation";
				}
				default: {
					return "UNKNOWN_FIELD_TYPE";
				}
			}
		}
		case -1: {
			switch(field_type) {
				default: {
					return "UNKNOWN_FIELD_TYPE";
				}
			}
		}
		case 4: {
			switch(field_type) {
				case 1: {
					return "EmailHash";
				}
				default: {
					return "UNKNOWN_FIELD_TYPE";
				}
			}
		}
		case 7: {
			switch(field_type) {
				case 1: {
					return "PublicKey";
				}
				case 2: {
					return "MessageKey";
				}
				case 3: {
					return "SigningPubKey";
				}
				case 4: {
					return "TxnSignature";
				}
				case 5: {
					return "Generator";
				}
				case 6: {
					return "Signature";
				}
				case 7: {
					return "Domain";
				}
				case 8: {
					return "FundCode";
				}
				case 9: {
					return "RemoveCode";
				}
				case 10: {
					return "ExpireCode";
				}
				case 11: {
					return "CreateCode";
				}
				case 12: {
					return "MemoType";
				}
				case 13: {
					return "MemoData";
				}
				case 14: {
					return "MemoFormat";
				}
				case 16: {
					return "Fulfillment";
				}
				case 17: {
					return "Condition";
				}
				case 18: {
					return "MasterSignature";
				}
				default: {
					return "UNKNOWN_FIELD_TYPE";
				}
			}
		}
		case 8: {
			switch(field_type) {
				case 1: {
					return "Account";
				}
				case 2: {
					return "Owner";
				}
				case 3: {
					return "Destination";
				}
				case 4: {
					return "Issuer";
				}
				case 5: {
					return "Authorize";
				}
				case 6: {
					return "Unauthorize";
				}
				case 7: {
					return "Target";
				}
				case 8: {
					return "RegularKey";
				}
				default: {
					return "UNKNOWN_FIELD_TYPE";
				}
			}
		}
		case 6: {
			switch(field_type) {
				case 1: {
					return "Amount";
				}
				case 2: {
					return "Balance";
				}
				case 3: {
					return "LimitAmount";
				}
				case 4: {
					return "TakerPays";
				}
				case 5: {
					return "TakerGets";
				}
				case 6: {
					return "LowLimit";
				}
				case 7: {
					return "HighLimit";
				}
				case 8: {
					return "Fee";
				}
				case 9: {
					return "SendMax";
				}
				case 10: {
					return "DeliverMin";
				}
				case 16: {
					return "MinimumOffer";
				}
				case 17: {
					return "RippleEscrow";
				}
				case 18: {
					return "DeliveredAmount";
				}
				case 258: {
					return "taker_gets_funded";
				}
				case 259: {
					return "taker_pays_funded";
				}
				default: {
					return "UNKNOWN_FIELD_TYPE";
				}
			}
		}
		case 5: {
			switch(field_type) {
				case 1: {
					return "LedgerHash";
				}
				case 2: {
					return "ParentHash";
				}
				case 3: {
					return "TransactionHash";
				}
				case 4: {
					return "AccountHash";
				}
				case 5: {
					return "PreviousTxnID";
				}
				case 6: {
					return "LedgerIndex";
				}
				case 7: {
					return "WalletLocator";
				}
				case 8: {
					return "RootIndex";
				}
				case 9: {
					return "AccountTxnID";
				}
				case 16: {
					return "BookDirectory";
				}
				case 17: {
					return "InvoiceID";
				}
				case 18: {
					return "Nickname";
				}
				case 19: {
					return "Amendment";
				}
				case 20: {
					return "TicketID";
				}
				case 21: {
					return "Digest";
				}
				case 257: {
					return "hash";
				}
				case 258: {
					return "index";
				}
				case 22: {
					return "Channel";
				}
				case 23: {
					return "ConsensusHash";
				}
				case 24: {
					return "CheckID";
				}
				default: {
					return "UNKNOWN_FIELD_TYPE";
				}
			}
		}
		case 16: {
			switch(field_type) {
				case 1: {
					return "CloseResolution";
				}
				case 2: {
					return "Method";
				}
				case 3: {
					return "TransactionResult";
				}
				case 16: {
					return "TickSize";
				}
				default: {
					return "UNKNOWN_FIELD_TYPE";
				}
			}
		}
		case 19: {
			switch(field_type) {
				case 1: {
					return "Indexes";
				}
				case 2: {
					return "Hashes";
				}
				case 3: {
					return "Amendments";
				}
				default: {
					return "UNKNOWN_FIELD_TYPE";
				}
			}
		}
		case 14: {
			switch(field_type) {
				case 1: {
					return "ObjectEndMarker";
				}
				case 2: {
					return "TransactionMetaData";
				}
				case 3: {
					return "CreatedNode";
				}
				case 4: {
					return "DeletedNode";
				}
				case 5: {
					return "ModifiedNode";
				}
				case 6: {
					return "PreviousFields";
				}
				case 7: {
					return "FinalFields";
				}
				case 8: {
					return "NewFields";
				}
				case 9: {
					return "TemplateEntry";
				}
				case 10: {
					return "Memo";
				}
				case 11: {
					return "SignerEntry";
				}
				case 16: {
					return "Signer";
				}
				case 18: {
					return "Majority";
				}
				default: {
					return "UNKNOWN_FIELD_TYPE";
				}
			}
		}
		case -2: {
			switch(field_type) {
				case 0: {
					return "Generic";
				}
				case -1: {
					return "Invalid";
				}
				default: {
					return "UNKNOWN_FIELD_TYPE";
				}
			}
		}
		case 10001: {
			switch(field_type) {
				case 1: {
					return "Transaction";
				}
				default: {
					return "UNKNOWN_FIELD_TYPE";
				}
			}
		}
		case 17: {
			switch(field_type) {
				case 1: {
					return "TakerPaysCurrency";
				}
				case 2: {
					return "TakerPaysIssuer";
				}
				case 3: {
					return "TakerGetsCurrency";
				}
				case 4: {
					return "TakerGetsIssuer";
				}
				default: {
					return "UNKNOWN_FIELD_TYPE";
				}
			}
		}
		case 18: {
			switch(field_type) {
				case 1: {
					return "Paths";
				}
				default: {
					return "UNKNOWN_FIELD_TYPE";
				}
			}
		}
		case 10002: {
			switch(field_type) {
				case 1: {
					return "LedgerEntry";
				}
				default: {
					return "UNKNOWN_FIELD_TYPE";
				}
			}
		}
		case 1: {
			switch(field_type) {
				case 1: {
					return "LedgerEntryType";
				}
				case 2: {
					return "TransactionType";
				}
				case 3: {
					return "SignerWeight";
				}
				default: {
					return "UNKNOWN_FIELD_TYPE";
				}
			}
		}
		case 0: {
			switch(field_type) {
				default: {
					return "UNKNOWN_FIELD_TYPE";
				}
			}
		}
		case 3: {
			switch(field_type) {
				case 1: {
					return "IndexNext";
				}
				case 2: {
					return "IndexPrevious";
				}
				case 3: {
					return "BookNode";
				}
				case 4: {
					return "OwnerNode";
				}
				case 5: {
					return "BaseFee";
				}
				case 6: {
					return "ExchangeRate";
				}
				case 7: {
					return "LowNode";
				}
				case 8: {
					return "HighNode";
				}
				case 9: {
					return "DestinationNode";
				}
				default: {
					return "UNKNOWN_FIELD_TYPE";
				}
			}
		}
		case 2: {
			switch(field_type) {
				case 2: {
					return "Flags";
				}
				case 3: {
					return "SourceTag";
				}
				case 4: {
					return "Sequence";
				}
				case 5: {
					return "PreviousTxnLgrSeq";
				}
				case 6: {
					return "LedgerSequence";
				}
				case 7: {
					return "CloseTime";
				}
				case 8: {
					return "ParentCloseTime";
				}
				case 9: {
					return "SigningTime";
				}
				case 10: {
					return "Expiration";
				}
				case 11: {
					return "TransferRate";
				}
				case 12: {
					return "WalletSize";
				}
				case 13: {
					return "OwnerCount";
				}
				case 14: {
					return "DestinationTag";
				}
				case 16: {
					return "HighQualityIn";
				}
				case 17: {
					return "HighQualityOut";
				}
				case 18: {
					return "LowQualityIn";
				}
				case 19: {
					return "LowQualityOut";
				}
				case 20: {
					return "QualityIn";
				}
				case 21: {
					return "QualityOut";
				}
				case 22: {
					return "StampEscrow";
				}
				case 23: {
					return "BondAmount";
				}
				case 24: {
					return "LoadFee";
				}
				case 25: {
					return "OfferSequence";
				}
				case 26: {
					return "FirstLedgerSequence";
				}
				case 27: {
					return "LastLedgerSequence";
				}
				case 28: {
					return "TransactionIndex";
				}
				case 29: {
					return "OperationLimit";
				}
				case 30: {
					return "ReferenceFeeUnits";
				}
				case 31: {
					return "ReserveBase";
				}
				case 32: {
					return "ReserveIncrement";
				}
				case 33: {
					return "SetFlag";
				}
				case 34: {
					return "ClearFlag";
				}
				case 35: {
					return "SignerQuorum";
				}
				case 36: {
					return "CancelAfter";
				}
				case 37: {
					return "FinishAfter";
				}
				case 38: {
					return "SignerListID";
				}
				case 39: {
					return "SettleDelay";
				}
				default: {
					return "UNKNOWN_FIELD_TYPE";
				}
			}
		}
		case 15: {
			switch(field_type) {
				case 1: {
					return "ArrayEndMarker";
				}
				case 3: {
					return "Signers";
				}
				case 4: {
					return "SignerEntries";
				}
				case 5: {
					return "Template";
				}
				case 6: {
					return "Necessary";
				}
				case 7: {
					return "Sufficient";
				}
				case 8: {
					return "AffectedNodes";
				}
				case 9: {
					return "Memos";
				}
				case 16: {
					return "Majorities";
				}
				default: {
					return "UNKNOWN_FIELD_TYPE";
				}
			}
		}
		default: {
			return "UNKNOWN_ST_TYPE";
		}
	}
}
inline int stlookup_field_info(int st_type, int field_type) {
	switch(st_type) {
		case 10003: {
			switch(field_type) {
				case 1: {
					return 0;
				}
				default: {
					return -1;
				}
			}
		}
		case -1: {
			switch(field_type) {
				default: {
					return -1;
				}
			}
		}
		case 4: {
			switch(field_type) {
				case 1: {
					return 3;
				}
				default: {
					return -1;
				}
			}
		}
		case 7: {
			switch(field_type) {
				case 1: {
					return 7;
				}
				case 2: {
					return 7;
				}
				case 3: {
					return 7;
				}
				case 4: {
					return 6;
				}
				case 5: {
					return 7;
				}
				case 6: {
					return 6;
				}
				case 7: {
					return 7;
				}
				case 8: {
					return 7;
				}
				case 9: {
					return 7;
				}
				case 10: {
					return 7;
				}
				case 11: {
					return 7;
				}
				case 12: {
					return 7;
				}
				case 13: {
					return 7;
				}
				case 14: {
					return 7;
				}
				case 16: {
					return 7;
				}
				case 17: {
					return 7;
				}
				case 18: {
					return 6;
				}
				default: {
					return -1;
				}
			}
		}
		case 8: {
			switch(field_type) {
				case 1: {
					return 7;
				}
				case 2: {
					return 7;
				}
				case 3: {
					return 7;
				}
				case 4: {
					return 7;
				}
				case 5: {
					return 7;
				}
				case 6: {
					return 7;
				}
				case 7: {
					return 7;
				}
				case 8: {
					return 7;
				}
				default: {
					return -1;
				}
			}
		}
		case 6: {
			switch(field_type) {
				case 1: {
					return 3;
				}
				case 2: {
					return 3;
				}
				case 3: {
					return 3;
				}
				case 4: {
					return 3;
				}
				case 5: {
					return 3;
				}
				case 6: {
					return 3;
				}
				case 7: {
					return 3;
				}
				case 8: {
					return 3;
				}
				case 9: {
					return 3;
				}
				case 10: {
					return 3;
				}
				case 16: {
					return 3;
				}
				case 17: {
					return 3;
				}
				case 18: {
					return 3;
				}
				case 258: {
					return 0;
				}
				case 259: {
					return 0;
				}
				default: {
					return -1;
				}
			}
		}
		case 5: {
			switch(field_type) {
				case 1: {
					return 3;
				}
				case 2: {
					return 3;
				}
				case 3: {
					return 3;
				}
				case 4: {
					return 3;
				}
				case 5: {
					return 3;
				}
				case 6: {
					return 3;
				}
				case 7: {
					return 3;
				}
				case 8: {
					return 3;
				}
				case 9: {
					return 3;
				}
				case 16: {
					return 3;
				}
				case 17: {
					return 3;
				}
				case 18: {
					return 3;
				}
				case 19: {
					return 3;
				}
				case 20: {
					return 3;
				}
				case 21: {
					return 3;
				}
				case 257: {
					return 0;
				}
				case 258: {
					return 0;
				}
				case 22: {
					return 3;
				}
				case 23: {
					return 3;
				}
				case 24: {
					return 3;
				}
				default: {
					return -1;
				}
			}
		}
		case 16: {
			switch(field_type) {
				case 1: {
					return 3;
				}
				case 2: {
					return 3;
				}
				case 3: {
					return 3;
				}
				case 16: {
					return 3;
				}
				default: {
					return -1;
				}
			}
		}
		case 19: {
			switch(field_type) {
				case 1: {
					return 7;
				}
				case 2: {
					return 7;
				}
				case 3: {
					return 7;
				}
				default: {
					return -1;
				}
			}
		}
		case 14: {
			switch(field_type) {
				case 1: {
					return 3;
				}
				case 2: {
					return 3;
				}
				case 3: {
					return 3;
				}
				case 4: {
					return 3;
				}
				case 5: {
					return 3;
				}
				case 6: {
					return 3;
				}
				case 7: {
					return 3;
				}
				case 8: {
					return 3;
				}
				case 9: {
					return 3;
				}
				case 10: {
					return 3;
				}
				case 11: {
					return 3;
				}
				case 16: {
					return 3;
				}
				case 18: {
					return 3;
				}
				default: {
					return -1;
				}
			}
		}
		case -2: {
			switch(field_type) {
				case 0: {
					return 0;
				}
				case -1: {
					return 0;
				}
				default: {
					return -1;
				}
			}
		}
		case 10001: {
			switch(field_type) {
				case 1: {
					return 0;
				}
				default: {
					return -1;
				}
			}
		}
		case 17: {
			switch(field_type) {
				case 1: {
					return 3;
				}
				case 2: {
					return 3;
				}
				case 3: {
					return 3;
				}
				case 4: {
					return 3;
				}
				default: {
					return -1;
				}
			}
		}
		case 18: {
			switch(field_type) {
				case 1: {
					return 3;
				}
				default: {
					return -1;
				}
			}
		}
		case 10002: {
			switch(field_type) {
				case 1: {
					return 0;
				}
				default: {
					return -1;
				}
			}
		}
		case 1: {
			switch(field_type) {
				case 1: {
					return 3;
				}
				case 2: {
					return 3;
				}
				case 3: {
					return 3;
				}
				default: {
					return -1;
				}
			}
		}
		case 0: {
			switch(field_type) {
				default: {
					return -1;
				}
			}
		}
		case 3: {
			switch(field_type) {
				case 1: {
					return 3;
				}
				case 2: {
					return 3;
				}
				case 3: {
					return 3;
				}
				case 4: {
					return 3;
				}
				case 5: {
					return 3;
				}
				case 6: {
					return 3;
				}
				case 7: {
					return 3;
				}
				case 8: {
					return 3;
				}
				case 9: {
					return 3;
				}
				default: {
					return -1;
				}
			}
		}
		case 2: {
			switch(field_type) {
				case 2: {
					return 3;
				}
				case 3: {
					return 3;
				}
				case 4: {
					return 3;
				}
				case 5: {
					return 3;
				}
				case 6: {
					return 3;
				}
				case 7: {
					return 3;
				}
				case 8: {
					return 3;
				}
				case 9: {
					return 3;
				}
				case 10: {
					return 3;
				}
				case 11: {
					return 3;
				}
				case 12: {
					return 3;
				}
				case 13: {
					return 3;
				}
				case 14: {
					return 3;
				}
				case 16: {
					return 3;
				}
				case 17: {
					return 3;
				}
				case 18: {
					return 3;
				}
				case 19: {
					return 3;
				}
				case 20: {
					return 3;
				}
				case 21: {
					return 3;
				}
				case 22: {
					return 3;
				}
				case 23: {
					return 3;
				}
				case 24: {
					return 3;
				}
				case 25: {
					return 3;
				}
				case 26: {
					return 3;
				}
				case 27: {
					return 3;
				}
				case 28: {
					return 3;
				}
				case 29: {
					return 3;
				}
				case 30: {
					return 3;
				}
				case 31: {
					return 3;
				}
				case 32: {
					return 3;
				}
				case 33: {
					return 3;
				}
				case 34: {
					return 3;
				}
				case 35: {
					return 3;
				}
				case 36: {
					return 3;
				}
				case 37: {
					return 3;
				}
				case 38: {
					return 3;
				}
				case 39: {
					return 3;
				}
				default: {
					return -1;
				}
			}
		}
		case 15: {
			switch(field_type) {
				case 1: {
					return 3;
				}
				case 3: {
					return 2;
				}
				case 4: {
					return 3;
				}
				case 5: {
					return 3;
				}
				case 6: {
					return 3;
				}
				case 7: {
					return 3;
				}
				case 8: {
					return 3;
				}
				case 9: {
					return 3;
				}
				case 16: {
					return 3;
				}
				default: {
					return -1;
				}
			}
		}
		default: {
			return -1;
		}
	}
}
