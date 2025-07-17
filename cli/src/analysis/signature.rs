use anyhow::{Result, anyhow};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use ds_decomp::{
    analysis::functions::Function,
    config::{module::Module, relocations::RelocationKind, symbol::SymbolMaps},
};
use serde::{Deserialize, Serialize};
use unarm::{ArmVersion, Endian, ParseFlags, ParseMode, Parser};

use crate::config::program::Program;

const SIGNATURES: &[(&str, &str)] = &[
    ("FS_LoadOverlay", include_str!("../../../assets/signatures/FS_LoadOverlay.yaml")),
    ("FS_UnloadOverlay", include_str!("../../../assets/signatures/FS_UnloadOverlay.yaml")),
    ("FX_Init", include_str!("../../../assets/signatures/FX_Init.yaml")),
    ("GX_Init", include_str!("../../../assets/signatures/GX_Init.yaml")),
    ("GX_HBlankIntr", include_str!("../../../assets/signatures/GX_HBlankIntr.yaml")),
    ("GX_VBlankIntr", include_str!("../../../assets/signatures/GX_VBlankIntr.yaml")),
    ("GX_DispOff", include_str!("../../../assets/signatures/GX_DispOff.yaml")),
    ("GX_SetGraphicsMode", include_str!("../../../assets/signatures/GX_SetGraphicsMode.yaml")),
    ("GXS_SetGraphicsMode", include_str!("../../../assets/signatures/GXS_SetGraphicsMode.yaml")),
    ("GX_SetBankForBG", include_str!("../../../assets/signatures/GX_SetBankForBG.yaml")),
    ("GX_SetBankForOBJ", include_str!("../../../assets/signatures/GX_SetBankForOBJ.yaml")),
    ("GX_SetBankForLCDC", include_str!("../../../assets/signatures/GX_SetBankForLCDC.yaml")),
    ("GX_SetBankForSubBG", include_str!("../../../assets/signatures/GX_SetBankForSubBG.yaml")),
    ("GX_SetBankForSubOBJ", include_str!("../../../assets/signatures/GX_SetBankForSubOBJ.yaml")),
    ("GX_DisableBankForLCDC", include_str!("../../../assets/signatures/GX_DisableBankForLCDC.yaml")),
    ("OS_Init", include_str!("../../../assets/signatures/OS_Init.yaml")),
    ("OS_InitTick", include_str!("../../../assets/signatures/OS_InitTick.yaml")),
    ("OS_InitAlarm", include_str!("../../../assets/signatures/OS_InitAlarm.yaml")),
    ("OS_WaitVBlankIntr", include_str!("../../../assets/signatures/OS_WaitVBlankIntr.yaml")),
    ("SND_Init", include_str!("../../../assets/signatures/SND_Init.yaml")),
    ("FS_Init", include_str!("../../../assets/signatures/FS_Init.yaml")),
    ("TP_Init", include_str!("../../../assets/signatures/TP_Init.yaml")),
    ("PM_GoSleepMode", include_str!("../../../assets/signatures/PM_GoSleepMode.yaml")),
    ("RTC_Init", include_str!("../../../assets/signatures/RTC_Init.yaml")),
    ("gsimalloc", include_str!("../../../assets/signatures/GameSpy/gsimalloc.yaml")),
    ("gsirealloc", include_str!("../../../assets/signatures/GameSpy/gsirealloc.yaml")),
    ("gsifree", include_str!("../../../assets/signatures/GameSpy/gsifree.yaml")),
    ("SOC_Socket", include_str!("../../../assets/signatures/GameSpy/SOC_Socket.yaml")),
    ("SOC_Connect", include_str!("../../../assets/signatures/GameSpy/SOC_Connect.yaml")),
    ("SOC_Recv", include_str!("../../../assets/signatures/GameSpy/SOC_Recv.yaml")),
    ("SOC_RecvFrom", include_str!("../../../assets/signatures/GameSpy/SOC_RecvFrom.yaml")),
    ("SOC_Send", include_str!("../../../assets/signatures/GameSpy/SOC_Send.yaml")),
    ("SOC_SendTo", include_str!("../../../assets/signatures/GameSpy/SOC_SendTo.yaml")),
    ("SOC_Close", include_str!("../../../assets/signatures/GameSpy/SOC_Close.yaml")),
    ("SOC_GetHostByName", include_str!("../../../assets/signatures/GameSpy/SOC_GetHostByName.yaml")),
    ("SOC_InetAtoN", include_str!("../../../assets/signatures/GameSpy/SOC_InetAtoN.yaml")),
    ("keyrand", include_str!("../../../assets/signatures/GameSpy/keyrand.yaml")),
    ("GOAHashInit", include_str!("../../../assets/signatures/GameSpy/GOAHashInit.yaml")),
    ("GOACryptInit", include_str!("../../../assets/signatures/GameSpy/GOACryptInit.yaml")),
    ("GOADecryptByte", include_str!("../../../assets/signatures/GameSpy/GOADecryptByte.yaml")),
    ("GOADecrypt", include_str!("../../../assets/signatures/GameSpy/GOADecrypt.yaml")),
    ("FIFOAddRear", include_str!("../../../assets/signatures/GameSpy/FIFOAddRear.yaml")),
    ("FIFOAddFront", include_str!("../../../assets/signatures/GameSpy/FIFOAddFront.yaml")),
    ("FIFOGetFirst", include_str!("../../../assets/signatures/GameSpy/FIFOGetFirst.yaml")),
    ("FIFORemove", include_str!("../../../assets/signatures/GameSpy/FIFORemove.yaml")),
    ("FIFOClear", include_str!("../../../assets/signatures/GameSpy/FIFOClear.yaml")),
    ("QEStartQuery", include_str!("../../../assets/signatures/GameSpy/QEStartQuery.yaml")),
    ("SBQueryEngineInit", include_str!("../../../assets/signatures/GameSpy/SBQueryEngineInit.yaml")),
    ("SBQueryEngineSetPublicIP", include_str!("../../../assets/signatures/GameSpy/SBQueryEngineSetPublicIP.yaml")),
    ("SBEngineHaltUpdates", include_str!("../../../assets/signatures/GameSpy/SBEngineHaltUpdates.yaml")),
    ("SBEngineCleanup", include_str!("../../../assets/signatures/GameSpy/SBEngineCleanup.yaml")),
    ("SBQueryEngineUpdateServer", include_str!("../../../assets/signatures/GameSpy/SBQueryEngineUpdateServer.yaml")),
    ("ParseSingleQR2Reply", include_str!("../../../assets/signatures/GameSpy/ParseSingleQR2Reply.yaml")),
    ("ParseSingleGOAReply", include_str!("../../../assets/signatures/GameSpy/ParseSingleGOAReply.yaml")),
    ("ParseSingleICMPReply", include_str!("../../../assets/signatures/GameSpy/ParseSingleICMPReply.yaml")),
    ("ProcessIncomingReplies", include_str!("../../../assets/signatures/GameSpy/ProcessIncomingReplies.yaml")),
    ("TimeoutOldQueries", include_str!("../../../assets/signatures/GameSpy/TimeoutOldQueries.yaml")),
    ("QueueNextQueries", include_str!("../../../assets/signatures/GameSpy/QueueNextQueries.yaml")),
    ("SBQueryEngineThink", include_str!("../../../assets/signatures/GameSpy/SBQueryEngineThink.yaml")),
    ("SBQueryEngineAddQueryKey", include_str!("../../../assets/signatures/GameSpy/SBQueryEngineAddQueryKey.yaml")),
    ("SBQueryEngineRemoveServerFromFIFOs", include_str!("../../../assets/signatures/GameSpy/SBQueryEngineRemoveServerFromFIFOs.yaml")),
    ("RefStringHash", include_str!("../../../assets/signatures/GameSpy/RefStringHash.yaml")),
    ("RefStringCompare", include_str!("../../../assets/signatures/GameSpy/RefStringCompare.yaml")),
    ("RefStringFree", include_str!("../../../assets/signatures/GameSpy/RefStringFree.yaml")),
    ("SBRefStrHash", include_str!("../../../assets/signatures/GameSpy/SBRefStrHash.yaml")),
    ("SBRefStrHashCleanup", include_str!("../../../assets/signatures/GameSpy/SBRefStrHashCleanup.yaml")),
    ("SBServerFree", include_str!("../../../assets/signatures/GameSpy/SBServerFree.yaml")),
    ("SBServerAddKeyValue", include_str!("../../../assets/signatures/GameSpy/SBServerAddKeyValue.yaml")),
    ("SBServerAddIntKeyValue", include_str!("../../../assets/signatures/GameSpy/SBServerAddIntKeyValue.yaml")),
    ("SBServerGetStringValueA", include_str!("../../../assets/signatures/GameSpy/SBServerGetStringValueA.yaml")),
    ("SBServerGetIntValueA", include_str!("../../../assets/signatures/GameSpy/SBServerGetIntValueA.yaml")),
    ("SBServerGetFloatValueA", include_str!("../../../assets/signatures/GameSpy/SBServerGetFloatValueA.yaml")),
    ("SBServerGetPublicInetAddress", include_str!("../../../assets/signatures/GameSpy/SBServerGetPublicInetAddress.yaml")),
    ("SBServerGetPublicQueryPort", include_str!("../../../assets/signatures/GameSpy/SBServerGetPublicQueryPort.yaml")),
    ("SBServerGetPublicQueryPortNBO", include_str!("../../../assets/signatures/GameSpy/SBServerGetPublicQueryPortNBO.yaml")),
    ("SBServerHasPrivateAddress", include_str!("../../../assets/signatures/GameSpy/SBServerHasPrivateAddress.yaml")),
    ("SBServerGetPrivateInetAddress", include_str!("../../../assets/signatures/GameSpy/SBServerGetPrivateInetAddress.yaml")),
    ("SBServerGetPrivateQueryPort", include_str!("../../../assets/signatures/GameSpy/SBServerGetPrivateQueryPort.yaml")),
    ("SBServerSetNext", include_str!("../../../assets/signatures/GameSpy/SBServerSetNext.yaml")),
    ("SBServerGetNext", include_str!("../../../assets/signatures/GameSpy/SBServerGetNext.yaml")),
    ("CheckValidKey", include_str!("../../../assets/signatures/GameSpy/CheckValidKey.yaml")),
    ("mytok", include_str!("../../../assets/signatures/GameSpy/mytok.yaml")),
    ("SBServerParseKeyVals", include_str!("../../../assets/signatures/GameSpy/SBServerParseKeyVals.yaml")),
    ("SBServerParseQR2FullKeysSingle", include_str!("../../../assets/signatures/GameSpy/SBServerParseQR2FullKeysSingle.yaml")),
    ("KeyValFree", include_str!("../../../assets/signatures/GameSpy/KeyValFree.yaml")),
    ("KeyValHashKey", include_str!("../../../assets/signatures/GameSpy/KeyValHashKey.yaml")),
    ("KeyValCompareKey", include_str!("../../../assets/signatures/GameSpy/KeyValCompareKey.yaml")),
    ("SBAllocServer", include_str!("../../../assets/signatures/GameSpy/SBAllocServer.yaml")),
    ("SBServerSetFlags", include_str!("../../../assets/signatures/GameSpy/SBServerSetFlags.yaml")),
    ("SBServerSetPrivateAddr", include_str!("../../../assets/signatures/GameSpy/SBServerSetPrivateAddr.yaml")),
    ("SBServerSetICMPIP", include_str!("../../../assets/signatures/GameSpy/SBServerSetICMPIP.yaml")),
    ("SBServerSetState", include_str!("../../../assets/signatures/GameSpy/SBServerSetState.yaml")),
    ("SBServerGetState", include_str!("../../../assets/signatures/GameSpy/SBServerGetState.yaml")),
    ("SBIsNullServer", include_str!("../../../assets/signatures/GameSpy/SBIsNullServer.yaml")),
    ("ListCallback", include_str!("../../../assets/signatures/GameSpy/ListCallback.yaml")),
    ("EngineCallback", include_str!("../../../assets/signatures/GameSpy/EngineCallback.yaml")),
    ("ServerBrowserNewA", include_str!("../../../assets/signatures/GameSpy/ServerBrowserNewA.yaml")),
    ("ServerBrowserFree", include_str!("../../../assets/signatures/GameSpy/ServerBrowserFree.yaml")),
    ("ServerBrowserBeginUpdate2", include_str!("../../../assets/signatures/GameSpy/ServerBrowserBeginUpdate2.yaml")),
    ("ServerBrowserLimitUpdateA", include_str!("../../../assets/signatures/GameSpy/ServerBrowserLimitUpdateA.yaml")),
    ("ServerBrowserSendMessageToServerA", include_str!("../../../assets/signatures/GameSpy/ServerBrowserSendMessageToServerA.yaml")),
    ("ServerBrowserSendNatNegotiateCookieToServerA", include_str!("../../../assets/signatures/GameSpy/ServerBrowserSendNatNegotiateCookieToServerA.yaml")),
    ("ServerBrowserRemoveServer", include_str!("../../../assets/signatures/GameSpy/ServerBrowserRemoveServer.yaml")),
    ("ServerBrowserThink", include_str!("../../../assets/signatures/GameSpy/ServerBrowserThink.yaml")),
    ("ServerBrowserHalt", include_str!("../../../assets/signatures/GameSpy/ServerBrowserHalt.yaml")),
    ("ServerBrowserClear", include_str!("../../../assets/signatures/GameSpy/ServerBrowserClear.yaml")),
    ("ServerBrowserState", include_str!("../../../assets/signatures/GameSpy/ServerBrowserState.yaml")),
    ("ServerBrowserGetServer", include_str!("../../../assets/signatures/GameSpy/ServerBrowserGetServer.yaml")),
    ("ServerBrowserCount", include_str!("../../../assets/signatures/GameSpy/ServerBrowserCount.yaml")),
    ("IntKeyCompare", include_str!("../../../assets/signatures/GameSpy/IntKeyCompare.yaml")),
    ("FloatKeyCompare", include_str!("../../../assets/signatures/GameSpy/FloatKeyCompare.yaml")),
    ("StrCaseKeyCompare", include_str!("../../../assets/signatures/GameSpy/StrCaseKeyCompare.yaml")),
    ("StrNoCaseKeyCompare", include_str!("../../../assets/signatures/GameSpy/StrNoCaseKeyCompare.yaml")),
    ("SBServerListSort", include_str!("../../../assets/signatures/GameSpy/SBServerListSort.yaml")),
    ("SBServerListAppendServer", include_str!("../../../assets/signatures/GameSpy/SBServerListAppendServer.yaml")),
    ("SBServerListFindServerByIP", include_str!("../../../assets/signatures/GameSpy/SBServerListFindServerByIP.yaml")),
    ("AddServerToDeadlist", include_str!("../../../assets/signatures/GameSpy/AddServerToDeadlist.yaml")),
    ("SBFreeDeadList", include_str!("../../../assets/signatures/GameSpy/SBFreeDeadList.yaml")),
    ("SBAllocateServerList", include_str!("../../../assets/signatures/GameSpy/SBAllocateServerList.yaml")),
    ("NTSLengthSB", include_str!("../../../assets/signatures/GameSpy/NTSLengthSB.yaml")),
    ("SBServerListInit", include_str!("../../../assets/signatures/GameSpy/SBServerListInit.yaml")),
    ("ErrorDisconnect", include_str!("../../../assets/signatures/GameSpy/ErrorDisconnect.yaml")),
    ("ServerListConnect", include_str!("../../../assets/signatures/GameSpy/ServerListConnect.yaml")),
    ("BufferAddNTS", include_str!("../../../assets/signatures/GameSpy/BufferAddNTS.yaml")),
    ("BufferAddByte", include_str!("../../../assets/signatures/GameSpy/BufferAddByte.yaml")),
    ("BufferAddInt", include_str!("../../../assets/signatures/GameSpy/BufferAddInt.yaml")),
    ("BufferAddData", include_str!("../../../assets/signatures/GameSpy/BufferAddData.yaml")),
    ("SetupListChallenge", include_str!("../../../assets/signatures/GameSpy/SetupListChallenge.yaml")),
    ("SendWithRetry", include_str!("../../../assets/signatures/GameSpy/SendWithRetry.yaml")),
    ("SBServerListConnectAndQuery", include_str!("../../../assets/signatures/GameSpy/SBServerListConnectAndQuery.yaml")),
    ("FreePopularValues", include_str!("../../../assets/signatures/GameSpy/FreePopularValues.yaml")),
    ("FreeKeyList", include_str!("../../../assets/signatures/GameSpy/FreeKeyList.yaml")),
    ("InitCryptKey", include_str!("../../../assets/signatures/GameSpy/InitCryptKey.yaml")),
    ("ServerSizeForFlags", include_str!("../../../assets/signatures/GameSpy/ServerSizeForFlags.yaml")),
    ("FullRulesPresent", include_str!("../../../assets/signatures/GameSpy/FullRulesPresent.yaml")),
    ("AllKeysPresent", include_str!("../../../assets/signatures/GameSpy/AllKeysPresent.yaml")),
    ("ParseServerIPPort", include_str!("../../../assets/signatures/GameSpy/ParseServerIPPort.yaml")),
    ("ParseServer", include_str!("../../../assets/signatures/GameSpy/ParseServer.yaml")),
    ("IncomingListParseServer", include_str!("../../../assets/signatures/GameSpy/IncomingListParseServer.yaml")),
    ("SBSetLastListErrorPtr", include_str!("../../../assets/signatures/GameSpy/SBSetLastListErrorPtr.yaml")),
    ("ProcessMainListData", include_str!("../../../assets/signatures/GameSpy/ProcessMainListData.yaml")),
    ("ProcessPushKeyList", include_str!("../../../assets/signatures/GameSpy/ProcessPushKeyList.yaml")),
    ("ProcessPlayerSearch", include_str!("../../../assets/signatures/GameSpy/ProcessPlayerSearch.yaml")),
    ("ProcessMaploop", include_str!("../../../assets/signatures/GameSpy/ProcessMaploop.yaml")),
    ("ProcessDeleteServer", include_str!("../../../assets/signatures/GameSpy/ProcessDeleteServer.yaml")),
    ("ProcessPushServer", include_str!("../../../assets/signatures/GameSpy/ProcessPushServer.yaml")),
    ("ProcessAdHocData", include_str!("../../../assets/signatures/GameSpy/ProcessAdHocData.yaml")),
    ("ProcessIncomingData", include_str!("../../../assets/signatures/GameSpy/ProcessIncomingData.yaml")),
    ("ProcessLanData", include_str!("../../../assets/signatures/GameSpy/ProcessLanData.yaml")),
    ("get_sockaddrin", include_str!("../../../assets/signatures/GameSpy/get_sockaddrin.yaml")),
    ("SendPacket", include_str!("../../../assets/signatures/GameSpy/SendPacket.yaml")),
    ("GSIStartAvailableCheckA", include_str!("../../../assets/signatures/GameSpy/GSIStartAvailableCheckA.yaml")),
    ("HandlePacket", include_str!("../../../assets/signatures/GameSpy/HandlePacket.yaml")),
    ("GSIAvailableCheckThink", include_str!("../../../assets/signatures/GameSpy/GSIAvailableCheckThink.yaml")),
    ("FreeElement", include_str!("../../../assets/signatures/GameSpy/FreeElement.yaml")),
    ("ArrayGrow", include_str!("../../../assets/signatures/GameSpy/ArrayGrow.yaml")),
    ("SetElement", include_str!("../../../assets/signatures/GameSpy/SetElement.yaml")),
    ("ArrayInsertAt", include_str!("../../../assets/signatures/GameSpy/ArrayInsertAt.yaml")),
    ("ArrayInsertSorted", include_str!("../../../assets/signatures/GameSpy/ArrayInsertSorted.yaml")),
    ("ArrayRemoveAt", include_str!("../../../assets/signatures/GameSpy/ArrayRemoveAt.yaml")),
    ("ArrayDeleteAt", include_str!("../../../assets/signatures/GameSpy/ArrayDeleteAt.yaml")),
    ("ArrayReplaceAt", include_str!("../../../assets/signatures/GameSpy/ArrayReplaceAt.yaml")),
    ("ArraySearch", include_str!("../../../assets/signatures/GameSpy/ArraySearch.yaml")),
    ("ArrayMapBackwards", include_str!("../../../assets/signatures/GameSpy/ArrayMapBackwards.yaml")),
    ("ArrayMapBackwards2", include_str!("../../../assets/signatures/GameSpy/ArrayMapBackwards2.yaml")),
    ("ArrayClear", include_str!("../../../assets/signatures/GameSpy/ArrayClear.yaml")),
    ("mylsearch", include_str!("../../../assets/signatures/GameSpy/mylsearch.yaml")),
    ("TableNew", include_str!("../../../assets/signatures/GameSpy/TableNew.yaml")),
    ("TableRemove", include_str!("../../../assets/signatures/GameSpy/TableRemove.yaml")),
    ("TableMapSafe", include_str!("../../../assets/signatures/GameSpy/TableMapSafe.yaml")),
    ("TableMapSafe2", include_str!("../../../assets/signatures/GameSpy/TableMapSafe2.yaml")),
    ("MD5Digest", include_str!("../../../assets/signatures/GameSpy/MD5Digest.yaml")),
    ("msleep", include_str!("../../../assets/signatures/GameSpy/msleep.yaml")),
    ("goastrdup", include_str!("../../../assets/signatures/GameSpy/goastrdup.yaml")),
    ("SetSockBlocking", include_str!("../../../assets/signatures/GameSpy/SetSockBlocking.yaml")),
    ("GSISocketSelect", include_str!("../../../assets/signatures/GameSpy/GSISocketSelect.yaml")),
    ("CheckRcode", include_str!("../../../assets/signatures/GameSpy/CheckRcode.yaml")),
    ("shutdown", include_str!("../../../assets/signatures/GameSpy/shutdown.yaml")),
    ("send", include_str!("../../../assets/signatures/GameSpy/send.yaml")),
    ("GOAGetLastError", include_str!("../../../assets/signatures/GameSpy/GOAGetLastError.yaml")),
    ("time", include_str!("../../../assets/signatures/GameSpy/time.yaml")),
    ("nextlongrand", include_str!("../../../assets/signatures/GameSpy/nextlongrand.yaml")),
    ("longrand", include_str!("../../../assets/signatures/GameSpy/longrand.yaml")),
    ("Util_RandSeed", include_str!("../../../assets/signatures/GameSpy/Util_RandSeed.yaml")),
    ("Util_RandInt", include_str!("../../../assets/signatures/GameSpy/Util_RandInt.yaml")),
    ("TripToQuart", include_str!("../../../assets/signatures/GameSpy/TripToQuart.yaml")),
    ("B64Encode", include_str!("../../../assets/signatures/GameSpy/B64Encode.yaml")),
    ("gpInitialize", include_str!("../../../assets/signatures/GameSpy/gpInitialize.yaml")),
    ("gpDestroy", include_str!("../../../assets/signatures/GameSpy/gpDestroy.yaml")),
    ("gpProcess", include_str!("../../../assets/signatures/GameSpy/gpProcess.yaml")),
    ("gpSetCallback", include_str!("../../../assets/signatures/GameSpy/gpSetCallback.yaml")),
    ("gpConnectPreAuthenticatedA", include_str!("../../../assets/signatures/GameSpy/gpConnectPreAuthenticatedA.yaml")),
    ("gpProfileSearchA", include_str!("../../../assets/signatures/GameSpy/gpProfileSearchA.yaml")),
    ("gpSetInfosA", include_str!("../../../assets/signatures/GameSpy/gpSetInfosA.yaml")),
    ("gpSendBuddyRequestA", include_str!("../../../assets/signatures/GameSpy/gpSendBuddyRequestA.yaml")),
    ("gpAuthBuddyRequest", include_str!("../../../assets/signatures/GameSpy/gpAuthBuddyRequest.yaml")),
    ("gpDenyBuddyRequest", include_str!("../../../assets/signatures/GameSpy/gpDenyBuddyRequest.yaml")),
    ("gpGetNumBuddies", include_str!("../../../assets/signatures/GameSpy/gpGetNumBuddies.yaml")),
    ("gpGetBuddyStatus", include_str!("../../../assets/signatures/GameSpy/gpGetBuddyStatus.yaml")),
    ("gpiResetProfile", include_str!("../../../assets/signatures/GameSpy/gpiResetProfile.yaml")),
    ("gpiReset", include_str!("../../../assets/signatures/GameSpy/gpiReset.yaml")),
    ("gpiProcessConnectionManager", include_str!("../../../assets/signatures/GameSpy/gpiProcessConnectionManager.yaml")),
    ("gpiSendAuthBuddyRequest", include_str!("../../../assets/signatures/GameSpy/gpiSendAuthBuddyRequest.yaml")),
    ("gpiProcessRecvBuddyMessage", include_str!("../../../assets/signatures/GameSpy/gpiProcessRecvBuddyMessage.yaml")),
    ("gpiSendServerBuddyMessage", include_str!("../../../assets/signatures/GameSpy/gpiSendServerBuddyMessage.yaml")),
    ("gpiSendBuddyMessage", include_str!("../../../assets/signatures/GameSpy/gpiSendBuddyMessage.yaml")),
    ("gpiFixBuddyIndices", include_str!("../../../assets/signatures/GameSpy/gpiFixBuddyIndices.yaml")),
    ("gpiDeleteBuddy", include_str!("../../../assets/signatures/GameSpy/gpiDeleteBuddy.yaml")),
    ("gpiAppendCharToBuffer", include_str!("../../../assets/signatures/GameSpy/gpiAppendCharToBuffer.yaml")),
    ("gpiAppendStringToBufferLen", include_str!("../../../assets/signatures/GameSpy/gpiAppendStringToBufferLen.yaml")),
    ("gpiSendData", include_str!("../../../assets/signatures/GameSpy/gpiSendData.yaml")),
    ("gpiSendOrBufferChar", include_str!("../../../assets/signatures/GameSpy/gpiSendOrBufferChar.yaml")),
    ("gpiSendOrBufferStringLen", include_str!("../../../assets/signatures/GameSpy/gpiSendOrBufferStringLen.yaml")),
    ("gpiSendOrBufferString", include_str!("../../../assets/signatures/GameSpy/gpiSendOrBufferString.yaml")),
    ("gpiRecvToBuffer", include_str!("../../../assets/signatures/GameSpy/gpiRecvToBuffer.yaml")),
    ("gpiSendFromBuffer", include_str!("../../../assets/signatures/GameSpy/gpiSendFromBuffer.yaml")),
    ("gpiReadMessageFromBuffer", include_str!("../../../assets/signatures/GameSpy/gpiReadMessageFromBuffer.yaml")),
    ("gpiClipBufferToPosition", include_str!("../../../assets/signatures/GameSpy/gpiClipBufferToPosition.yaml")),
    ("gpiCallErrorCallback", include_str!("../../../assets/signatures/GameSpy/gpiCallErrorCallback.yaml")),
    ("gpiAddCallback", include_str!("../../../assets/signatures/GameSpy/gpiAddCallback.yaml")),
    ("gpiCallCallback", include_str!("../../../assets/signatures/GameSpy/gpiCallCallback.yaml")),
    ("gpiProcessCallbacks", include_str!("../../../assets/signatures/GameSpy/gpiProcessCallbacks.yaml")),
    ("randomString", include_str!("../../../assets/signatures/GameSpy/randomString.yaml")),
    ("gpiStartConnect", include_str!("../../../assets/signatures/GameSpy/gpiStartConnect.yaml")),
    ("gpiSendLogin", include_str!("../../../assets/signatures/GameSpy/gpiSendLogin.yaml")),
    ("gpiSendNewuser", include_str!("../../../assets/signatures/GameSpy/gpiSendNewuser.yaml")),
    ("gpiProcessConnect", include_str!("../../../assets/signatures/GameSpy/gpiProcessConnect.yaml")),
    ("gpiCheckConnect", include_str!("../../../assets/signatures/GameSpy/gpiCheckConnect.yaml")),
    ("gpiDisconnectCleanupProfile", include_str!("../../../assets/signatures/GameSpy/gpiDisconnectCleanupProfile.yaml")),
    ("gpiDisconnect", include_str!("../../../assets/signatures/GameSpy/gpiDisconnect.yaml")),
    ("gpiIsValidDate", include_str!("../../../assets/signatures/GameSpy/gpiIsValidDate.yaml")),
    ("gpiIntToDate", include_str!("../../../assets/signatures/GameSpy/gpiIntToDate.yaml")),
    ("gpiInfoCacheToArg", include_str!("../../../assets/signatures/GameSpy/gpiInfoCacheToArg.yaml")),
    ("gpiProcessGetInfo", include_str!("../../../assets/signatures/GameSpy/gpiProcessGetInfo.yaml")),
    ("gpiAddLocalInfo", include_str!("../../../assets/signatures/GameSpy/gpiAddLocalInfo.yaml")),
    ("gpiSendLocalInfo", include_str!("../../../assets/signatures/GameSpy/gpiSendLocalInfo.yaml")),
    ("gpiSendUserInfo", include_str!("../../../assets/signatures/GameSpy/gpiSendUserInfo.yaml")),
    ("gpiSetInfoi", include_str!("../../../assets/signatures/GameSpy/gpiSetInfoi.yaml")),
    ("gpiSendGetInfo", include_str!("../../../assets/signatures/GameSpy/gpiSendGetInfo.yaml")),
    ("gpiGetInfo", include_str!("../../../assets/signatures/GameSpy/gpiGetInfo.yaml")),
    ("gpiSetInfoCache", include_str!("../../../assets/signatures/GameSpy/gpiSetInfoCache.yaml")),
    ("gpiFailedOpCallback", include_str!("../../../assets/signatures/GameSpy/gpiFailedOpCallback.yaml")),
    ("gpiAddOperation", include_str!("../../../assets/signatures/GameSpy/gpiAddOperation.yaml")),
    ("gpiDestroyOperation", include_str!("../../../assets/signatures/GameSpy/gpiDestroyOperation.yaml")),
    ("gpiFindOperationByID", include_str!("../../../assets/signatures/GameSpy/gpiFindOperationByID.yaml")),
    ("gpiOperationsAreBlocking", include_str!("../../../assets/signatures/GameSpy/gpiOperationsAreBlocking.yaml")),
    ("gpiProcessOperation", include_str!("../../../assets/signatures/GameSpy/gpiProcessOperation.yaml")),
    ("gpiProcessPeerInitiatingConnection", include_str!("../../../assets/signatures/GameSpy/gpiProcessPeerInitiatingConnection.yaml")),
    ("gpiProcessPeerAcceptingConnection", include_str!("../../../assets/signatures/GameSpy/gpiProcessPeerAcceptingConnection.yaml")),
    ("gpiPeerSendMessages", include_str!("../../../assets/signatures/GameSpy/gpiPeerSendMessages.yaml")),
    ("gpiProcessPeer", include_str!("../../../assets/signatures/GameSpy/gpiProcessPeer.yaml")),
    ("gpiRemovePeer", include_str!("../../../assets/signatures/GameSpy/gpiRemovePeer.yaml")),
    ("gpiProcessPeers", include_str!("../../../assets/signatures/GameSpy/gpiProcessPeers.yaml")),
    ("gpiGetPeerByProfile", include_str!("../../../assets/signatures/GameSpy/gpiGetPeerByProfile.yaml")),
    ("gpiAddPeer", include_str!("../../../assets/signatures/GameSpy/gpiAddPeer.yaml")),
    ("gpiPeerGetSig", include_str!("../../../assets/signatures/GameSpy/gpiPeerGetSig.yaml")),
    ("gpiPeerStartConnect", include_str!("../../../assets/signatures/GameSpy/gpiPeerStartConnect.yaml")),
    ("gpiPeerAddMessage", include_str!("../../../assets/signatures/GameSpy/gpiPeerAddMessage.yaml")),
    ("gpiPeerStartTransferMessage", include_str!("../../../assets/signatures/GameSpy/gpiPeerStartTransferMessage.yaml")),
    ("gpiPeerFinishTransferMessage", include_str!("../../../assets/signatures/GameSpy/gpiPeerFinishTransferMessage.yaml")),
    ("gpiProfilesTableHash", include_str!("../../../assets/signatures/GameSpy/gpiProfilesTableHash.yaml")),
    ("gpiProfilesTableCompare", include_str!("../../../assets/signatures/GameSpy/gpiProfilesTableCompare.yaml")),
    ("gpiProfilesTableFree", include_str!("../../../assets/signatures/GameSpy/gpiProfilesTableFree.yaml")),
    ("gpiInitProfiles", include_str!("../../../assets/signatures/GameSpy/gpiInitProfiles.yaml")),
    ("gpiProfileListAdd", include_str!("../../../assets/signatures/GameSpy/gpiProfileListAdd.yaml")),
    ("gpiRemoveProfileByID", include_str!("../../../assets/signatures/GameSpy/gpiRemoveProfileByID.yaml")),
    ("gpiCheckProfileForUser", include_str!("../../../assets/signatures/GameSpy/gpiCheckProfileForUser.yaml")),
    ("gpiFindProfileByUser", include_str!("../../../assets/signatures/GameSpy/gpiFindProfileByUser.yaml")),
    ("gpiProfileMapCallback", include_str!("../../../assets/signatures/GameSpy/gpiProfileMapCallback.yaml")),
    ("gpiCheckForBuddy", include_str!("../../../assets/signatures/GameSpy/gpiCheckForBuddy.yaml")),
    ("gpiStartProfileSearch", include_str!("../../../assets/signatures/GameSpy/gpiStartProfileSearch.yaml")),
    ("gpiInitSearchData", include_str!("../../../assets/signatures/GameSpy/gpiInitSearchData.yaml")),
    ("gpiStartSearch", include_str!("../../../assets/signatures/GameSpy/gpiStartSearch.yaml")),
    ("gpiProcessSearch", include_str!("../../../assets/signatures/GameSpy/gpiProcessSearch.yaml")),
    ("gpiProcessSearches", include_str!("../../../assets/signatures/GameSpy/gpiProcessSearches.yaml")),
    ("gpiSendTransferReply", include_str!("../../../assets/signatures/GameSpy/gpiSendTransferReply.yaml")),
    ("gpiHandleTransferMessage", include_str!("../../../assets/signatures/GameSpy/gpiHandleTransferMessage.yaml")),
    ("gpiCheckForError", include_str!("../../../assets/signatures/GameSpy/gpiCheckForError.yaml")),
    ("gpiReadKeyAndValue", include_str!("../../../assets/signatures/GameSpy/gpiReadKeyAndValue.yaml")),
    ("BucketNew", include_str!("../../../assets/signatures/GameSpy/BucketNew.yaml")),
    ("BucketSet", include_str!("../../../assets/signatures/GameSpy/BucketSet.yaml")),
    ("BucketAdd", include_str!("../../../assets/signatures/GameSpy/BucketAdd.yaml")),
    ("BucketSub", include_str!("../../../assets/signatures/GameSpy/BucketSub.yaml")),
    ("BucketMult", include_str!("../../../assets/signatures/GameSpy/BucketMult.yaml")),
    ("BucketDiv", include_str!("../../../assets/signatures/GameSpy/BucketDiv.yaml")),
    ("BucketConcat", include_str!("../../../assets/signatures/GameSpy/BucketConcat.yaml")),
    ("BucketAvg", include_str!("../../../assets/signatures/GameSpy/BucketAvg.yaml")),
    ("stripchars", include_str!("../../../assets/signatures/GameSpy/stripchars.yaml")),
    ("CloseStatsConnection", include_str!("../../../assets/signatures/GameSpy/CloseStatsConnection.yaml")),
    ("IsStatsConnected", include_str!("../../../assets/signatures/GameSpy/IsStatsConnected.yaml")),
    ("PersistThink", include_str!("../../../assets/signatures/GameSpy/PersistThink.yaml")),
    ("xcode_buf", include_str!("../../../assets/signatures/GameSpy/xcode_buf.yaml")),
    ("value_for_key", include_str!("../../../assets/signatures/GameSpy/value_for_key.yaml")),
    ("value_for_key_safe", include_str!("../../../assets/signatures/GameSpy/value_for_key_safe.yaml")),
    ("SocketReadable", include_str!("../../../assets/signatures/GameSpy/SocketReadable.yaml")),
    ("FindFinal", include_str!("../../../assets/signatures/GameSpy/FindFinal.yaml")),
    ("FindRequest", include_str!("../../../assets/signatures/GameSpy/FindRequest.yaml")),
    ("ProcessPlayerAuth", include_str!("../../../assets/signatures/GameSpy/ProcessPlayerAuth.yaml")),
    ("ProcessGetPid", include_str!("../../../assets/signatures/GameSpy/ProcessGetPid.yaml")),
    ("ProcessGetData", include_str!("../../../assets/signatures/GameSpy/ProcessGetData.yaml")),
    ("ProcessSetData", include_str!("../../../assets/signatures/GameSpy/ProcessSetData.yaml")),
    ("ProcessStatement", include_str!("../../../assets/signatures/GameSpy/ProcessStatement.yaml")),
    ("ProcessInBuffer", include_str!("../../../assets/signatures/GameSpy/ProcessInBuffer.yaml")),
    ("GetTeamIndex", include_str!("../../../assets/signatures/GameSpy/GetTeamIndex.yaml")),
    ("GetPlayerIndex", include_str!("../../../assets/signatures/GameSpy/GetPlayerIndex.yaml")),
    ("ServerOpInt", include_str!("../../../assets/signatures/GameSpy/ServerOpInt.yaml")),
    ("ServerOpFloat", include_str!("../../../assets/signatures/GameSpy/ServerOpFloat.yaml")),
    ("ServerOpString", include_str!("../../../assets/signatures/GameSpy/ServerOpString.yaml")),
    ("TeamOpInt", include_str!("../../../assets/signatures/GameSpy/TeamOpInt.yaml")),
    ("TeamOpFloat", include_str!("../../../assets/signatures/GameSpy/TeamOpFloat.yaml")),
    ("TeamOpString", include_str!("../../../assets/signatures/GameSpy/TeamOpString.yaml")),
    ("PlayerOpInt", include_str!("../../../assets/signatures/GameSpy/PlayerOpInt.yaml")),
    ("PlayerOpFloat", include_str!("../../../assets/signatures/GameSpy/PlayerOpFloat.yaml")),
    ("PlayerOpString", include_str!("../../../assets/signatures/GameSpy/PlayerOpString.yaml")),
    ("gti2VerifyChallenge", include_str!("../../../assets/signatures/GameSpy/gti2VerifyChallenge.yaml")),
    ("gti2GetChallenge", include_str!("../../../assets/signatures/GameSpy/gti2GetChallenge.yaml")),
    ("gti2GetResponse", include_str!("../../../assets/signatures/GameSpy/gti2GetResponse.yaml")),
    ("gti2CheckResponse", include_str!("../../../assets/signatures/GameSpy/gti2CheckResponse.yaml")),
    ("gti2AllocateBuffer", include_str!("../../../assets/signatures/GameSpy/gti2AllocateBuffer.yaml")),
    ("gti2GetBufferFreeSpace", include_str!("../../../assets/signatures/GameSpy/gti2GetBufferFreeSpace.yaml")),
    ("gti2BufferWriteByte", include_str!("../../../assets/signatures/GameSpy/gti2BufferWriteByte.yaml")),
    ("gti2BufferWriteUShort", include_str!("../../../assets/signatures/GameSpy/gti2BufferWriteUShort.yaml")),
    ("gti2BufferWriteData", include_str!("../../../assets/signatures/GameSpy/gti2BufferWriteData.yaml")),
    ("gti2BufferShorten", include_str!("../../../assets/signatures/GameSpy/gti2BufferShorten.yaml")),
    ("gti2SocketErrorCallback", include_str!("../../../assets/signatures/GameSpy/gti2SocketErrorCallback.yaml")),
    ("gti2ConnectAttemptCallback", include_str!("../../../assets/signatures/GameSpy/gti2ConnectAttemptCallback.yaml")),
    ("gti2ConnectedCallback", include_str!("../../../assets/signatures/GameSpy/gti2ConnectedCallback.yaml")),
    ("gti2ReceivedCallback", include_str!("../../../assets/signatures/GameSpy/gti2ReceivedCallback.yaml")),
    ("gti2ClosedCallback", include_str!("../../../assets/signatures/GameSpy/gti2ClosedCallback.yaml")),
    ("gti2PingCallback", include_str!("../../../assets/signatures/GameSpy/gti2PingCallback.yaml")),
    ("gti2SendFilterCallback", include_str!("../../../assets/signatures/GameSpy/gti2SendFilterCallback.yaml")),
    ("gti2ReceiveFilterCallback", include_str!("../../../assets/signatures/GameSpy/gti2ReceiveFilterCallback.yaml")),
    ("gti2DumpCallback", include_str!("../../../assets/signatures/GameSpy/gti2DumpCallback.yaml")),
    ("gti2UnrecognizedMessageCallback", include_str!("../../../assets/signatures/GameSpy/gti2UnrecognizedMessageCallback.yaml")),
    ("gt2SetConnectionData", include_str!("../../../assets/signatures/GameSpy/gt2SetConnectionData.yaml")),
    ("gt2GetConnectionData", include_str!("../../../assets/signatures/GameSpy/gt2GetConnectionData.yaml")),
    ("gti2EndReliableMessage", include_str!("../../../assets/signatures/GameSpy/gti2EndReliableMessage.yaml")),
    ("gti2FilteredReceive", include_str!("../../../assets/signatures/GameSpy/gti2FilteredReceive.yaml")),
    ("gt2StringToAddress", include_str!("../../../assets/signatures/GameSpy/gt2StringToAddress.yaml")),
];

#[derive(Serialize, Deserialize)]
pub struct Signatures {
    /// The function name these signatures are for.
    name: String,
    signatures: Vec<Signature>,
}

#[derive(Clone, Copy)]
pub struct SignatureIndex(usize);

#[derive(Serialize, Deserialize)]
pub struct Signature {
    #[serde(flatten)]
    mask: SignatureMask,
    /// External references within this function, if any, such as function calls or data accesses.
    relocations: Vec<SignatureRelocation>,
}

struct SignatureMask {
    bitmask: Vec<u8>,
    pattern: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone)]
struct SignatureRelocation {
    /// Offset within the function code where this relocation occurs.
    offset: usize,
    /// Name of the object this relocation points to.
    name: String,
    kind: RelocationKind,
    #[serde(skip_serializing_if = "is_zero", default)]
    addend: i32,
}

fn is_zero(value: &i32) -> bool {
    *value == 0
}

pub enum ApplyResult {
    /// The signature was successfully applied.
    Applied,
    /// The signature was not applied because it did not match any function.
    NotFound,
    /// The signature was not applied because multiple functions matched.
    MultipleFound,
}

impl Signatures {
    pub fn from_function(function: &Function, module: &Module, symbol_maps: &SymbolMaps) -> Result<Self> {
        let function_code = function.code(module.code(), module.base_address());

        let parse_mode = if function.is_thumb() { ParseMode::Thumb } else { ParseMode::Arm };
        let mut parser = Parser::new(
            parse_mode,
            function.start_address(),
            Endian::Little,
            ParseFlags { version: ArmVersion::V5Te, ual: false },
            function_code,
        );
        let mut bitmask = Vec::new();
        let mut pattern = Vec::new();
        let bl_offset_bits = if function.is_thumb() { 0x07ff07ff } else { 0x00ffffff };
        for (address, ins, parsed_ins) in parser {
            let mut ins_bitmask: u32 = 0xffffffff;

            if function.pool_constants().contains(&address) {
                // TODO: Only mask out pool constants which are pointers?
                parser.seek_forward(address + 4); // Skip pool constants
                bitmask.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
                pattern.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
                continue;
            }

            // Mask out function call addresses
            let mnemonic = ins.mnemonic();
            let is_bl_immediate = mnemonic == "bl" || mnemonic == "blx" && parsed_ins.branch_destination().is_some();
            if is_bl_immediate {
                ins_bitmask &= !bl_offset_bits;
            }

            let ins_size = if !function.is_thumb() || is_bl_immediate { 4 } else { 2 };
            let start = address - function.start_address();
            let end = start + ins_size as u32;
            let code = &function_code[start as usize..end as usize];

            let bitmask_bytes = &ins_bitmask.to_le_bytes()[..ins_size];
            let pattern_bytes = code.iter().zip(bitmask_bytes).map(|(&b, &m)| b & m);

            bitmask.extend_from_slice(bitmask_bytes);
            pattern.extend(pattern_bytes);
        }

        let relocations = module
            .relocations()
            .iter_range(function.start_address()..function.end_address())
            .filter_map(|(&address, relocation)| {
                let module_kind = relocation.destination_module()?;
                let dest_symbol_map = symbol_maps.get(module_kind)?;
                let (_, dest_symbol) = match dest_symbol_map.by_address(relocation.to_address()) {
                    Ok(symbol) => symbol?,
                    Err(e) => return Some(Err(e.into())),
                };
                Some(Ok(SignatureRelocation {
                    name: dest_symbol.name.clone(),
                    offset: (address - function.start_address()) as usize,
                    addend: relocation.addend_value(),
                    kind: relocation.kind(),
                }))
            })
            .collect::<Result<Vec<_>>>()?;

        Ok(Self {
            name: function.name().to_string(),
            signatures: vec![Signature { mask: SignatureMask { bitmask, pattern }, relocations }],
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn list() -> Result<Vec<Self>> {
        SIGNATURES
            .iter()
            .map(|(name, yaml)| serde_yml::from_str(yaml).map_err(|e| anyhow!("Failed to parse signature '{}': {}", name, e)))
            .collect::<Result<Vec<_>>>()
    }

    pub fn get(name: &str) -> Result<Self> {
        let signature_str = SIGNATURES
            .iter()
            .find(|(signature_name, _)| *signature_name == name)
            .ok_or_else(|| anyhow!("Signature '{}' not found", name))?;
        serde_yml::from_str(signature_str.1).map_err(|e| anyhow!("Failed to parse signature '{}': {}", name, e))
    }

    pub fn iter_names() -> impl Iterator<Item = &'static str> + 'static {
        SIGNATURES.iter().map(|(name, _)| *name)
    }

    pub fn apply(&self, program: &mut Program) -> Result<ApplyResult> {
        let matches = program
            .modules()
            .iter()
            .flat_map(|module| {
                self.find_matches(module)
                    .map(move |(function, signature)| (function.start_address(), module.kind(), signature))
            })
            .collect::<Vec<_>>();
        if matches.is_empty() {
            Ok(ApplyResult::NotFound)
        } else if matches.len() > 1 {
            Ok(ApplyResult::MultipleFound)
        } else {
            let (function_address, module_kind, signature_index) = matches[0];
            let signature = &self.signatures[signature_index.0];

            {
                let symbol_maps = program.symbol_maps_mut();
                let symbol_map = symbol_maps.get_mut(module_kind);
                let changed = symbol_map.rename_by_address(function_address, &self.name)?;
                if changed {
                    log::info!("Renamed function at {:#010x} in {} to '{}'", function_address, module_kind, self.name);
                }
            }

            let module = program.by_module_kind_mut(module_kind).unwrap();
            let relocations = module.relocations_mut();

            let mut symbol_updates = vec![];
            for sig_relocation in &signature.relocations {
                let address = function_address + sig_relocation.offset as u32;
                let Some(relocation) = relocations.get_mut(address) else {
                    log::warn!(
                        "Relocation '{}' for signature '{}' not found at address {:#010x} in {}",
                        sig_relocation.name,
                        self.name,
                        address,
                        module_kind
                    );
                    continue;
                };
                let Some(destination_module) = relocation.destination_module() else {
                    log::warn!(
                        "Skipping ambiguous relocation '{}' for signature '{}' at address {:#010x} in {}",
                        sig_relocation.name,
                        self.name,
                        address,
                        module_kind
                    );
                    continue;
                };

                if relocation.kind() != sig_relocation.kind || relocation.addend_value() != sig_relocation.addend {
                    relocation.set_kind(sig_relocation.kind);
                    relocation.set_addend(sig_relocation.addend);
                    log::info!("Updated relocation '{}' at address {:#010x} in {}", sig_relocation.name, address, module_kind);
                }

                symbol_updates.push((destination_module, relocation.to_address(), &sig_relocation.name));
            }

            for (destination_module, to_address, name) in symbol_updates.into_iter() {
                let symbol_maps = program.symbol_maps_mut();
                let dest_symbol_map = symbol_maps.get_mut(destination_module);
                let changed = dest_symbol_map.rename_by_address(to_address, name)?;
                if changed {
                    log::info!("Renamed symbol at {:#010x} in {} to '{}'", to_address, destination_module, name);
                }
            }

            Ok(ApplyResult::Applied)
        }
    }

    pub fn find_matches<'a>(&'a self, module: &'a Module) -> impl Iterator<Item = (&'a Function, SignatureIndex)> + 'a {
        module
            .sections()
            .functions()
            .filter_map(|function| self.match_signature(function, module).map(|signature| (function, signature)))
    }

    pub fn match_signature(&self, function: &Function, module: &Module) -> Option<SignatureIndex> {
        self.signatures
            .iter()
            .enumerate()
            .find_map(|(index, signature)| signature.matches(function, module).then_some(SignatureIndex(index)))
    }
}

impl Signature {
    pub fn matches(&self, function: &Function, module: &Module) -> bool {
        if function.size() as usize != self.mask.pattern.len() {
            return false;
        }
        function
            .code(module.code(), module.base_address())
            .iter()
            .zip(self.mask.bitmask.iter())
            .zip(self.mask.pattern.iter())
            .all(|((&code, &bitmask), &pattern)| (code & bitmask) == pattern)
    }
}

#[derive(Deserialize, Serialize)]
struct SignatureMaskData {
    bitmask: String,
    pattern: String,
}

impl Serialize for SignatureMask {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let data = SignatureMaskData { bitmask: STANDARD.encode(&self.bitmask), pattern: STANDARD.encode(&self.pattern) };
        data.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for SignatureMask {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let data = SignatureMaskData::deserialize(deserializer)?;
        let bitmask = STANDARD.decode(data.bitmask).map_err(serde::de::Error::custom)?;
        let pattern = STANDARD.decode(data.pattern).map_err(serde::de::Error::custom)?;
        Ok(SignatureMask { bitmask, pattern })
    }
}
