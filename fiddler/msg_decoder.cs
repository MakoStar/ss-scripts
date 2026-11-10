// ============================================================
//                   SS 抓包解码脚本
// ============================================================
// 用于 Fiddler Everywhere，自动解开并展示游戏加密报文(不完整)。
//
// 使用方法
//   1 把本文件粘到 Fiddler Everywhere 的脚本编辑器
//   2 按区服修改 SS_REGION，保持 SS_MITM 开启
//   3 保存后启动 Fiddler，再启动游戏重新握手
//   4 列表里紫色是游戏报文，蓝色是静态资源，点 Body 看明文
//     Comments 列显示 msgId nonce key3
//
// 只想旁观不改包就把 SS_MITM 关掉，此时需要手填 key3
// ============================================================

// 区服 CN JP KR EN TW
static string SS_REGION       = "CN";

// 中转开关，默认开启，自动算出 key3
static bool   SS_MITM         = true;

// 中转用的两对私钥，一次性的，可自行替换
// python -c "import secrets; print(secrets.token_hex(32))"
static string SS_F1_PRIV_HEX  = "749f07329dbdefecf03371286ff14a76570fe152b38dd346e65afe5f1dc4642c";
static string SS_F2_PRIV_HEX  = "599b71486de02d56ec3ddf257f7340772f1fa8a43de6542c2cd4b956541eec1d";

// 关闭中转时手填 key3
static string SS_KEY3_HEX     = "";

// 关闭中转时手填客户端私钥
static string SS_CLIENT_PRIV_HEX = "";

// 外部工具注入的 key3
static string SS_KEY3_LIVE    = "";

// 明文写回方式 2 是 JSON，1 是 protobuf，0 不写
static int    SS_UI_BODY      = 2;

// 是否处理请求方向
static bool   SS_UI_BODY_REQ  = true;

// 是否处理响应方向
static bool   SS_UI_BODY_RESP = true;

// JSON 长度上限，超过退回 protobuf
static int    SS_UI_BODY_MAX  = 512000;

// 是否在列表里标色
static bool   SS_MARK_COLOR   = true;

// 是否处理 serverlist 与 noticelist
static bool   SS_STATIC_META  = true;

// key3 注入失败时是否留一行提示
static bool   SS_NOTE_FAIL    = true;

// 是否在 Comments 显示 msgId nonce key3
static bool   SS_COMMENT_INFO = true;

// ============================================================
// 运行时状态
// ============================================================

static byte[] SS_ClientPub   = null;
static byte[] SS_ServerPub   = null;
static byte[] SS_DerivedKey3 = null;
static int    SS_IkeCipher   = -1;
static string SS_IkeToken    = null;
static long   SS_IkeServerTs = 0;
static byte[] SS_MitmF1Pub   = null;
static byte[] SS_MitmF2Pub   = null;
static byte[] SS_MitmCliPub  = null;
static byte[] SS_MitmSrvPub  = null;
static byte[] SS_MitmKCli    = null;
static byte[] SS_MitmKSrv    = null;
static byte[] SS_LastKey     = null;
static string SS_LastKeyName = null;
static byte[] SS_LastNonce   = null;
static string SS_LastResolved = null;
static int    SS_MitmRelayCnt = 0;
static int    SS_MitmFail    = 0;
static bool   SS_MitmWarned  = false;

static System.Collections.Generic.Dictionary<string, string> SS_GARBLE =
    new System.Collections.Generic.Dictionary<string, string>
{
    { "CN", "QW*Wi7fKjLk!T82Qf2nEGZA%nSC!D9qV" },
    { "JP", "yX5Gt64PVvVH6$qwBXaPJC*LZKoK5mYh" },
    { "KR", "25hdume9H#*6hHn@d9hSF7tekTwN#JYj" },
    { "EN", "xNdVF^XTa6T3HCUATMQ@sKMLzAw&%L!3" },
    { "TW", "N&mfco452ZH5!nE3s&o5uxB57UGPENVo" }
};

static System.Collections.Generic.Dictionary<string, string> SS_STATIC_KEYS =
    new System.Collections.Generic.Dictionary<string, string>
{
    { "CN", "Xf&FRcsYm48cJ2A@" },
    { "EN", "ma5Dn2FhC*Xhxy%c" },
    { "JP", "ZnUFA@S9%4KyoryM" },
    { "KR", "U9cjHuwGDDx&$drn" },
    { "TW", "owGYVDmfHrxi^4pm" }
};

static System.Collections.Generic.Dictionary<string, string> SS_STATIC_HOSTREGION =
    new System.Collections.Generic.Dictionary<string, string>
{
    { "nova-static.yostar.cn",            "CN" },
    { "nova-static.stellasora.global",    "EN" },
    { "nova-static.stellasora.jp",        "JP" },
    { "nova-static.stellasora.kr",        "KR" },
    { "nova-static.stargazer-games.com",  "TW" }
};

static string SS_MAP_STR =
    "-10059:GmHandbookCompleteNotify|-10058:GmClearAllActivityMathParkourLevelsNotify|-10057:GmClearAllActivityIceCreamLevelsNotify|-10056:SoldierEffectNtf|-10055:SoldierInfo|-10054:ShopCaseData|-10053:ChangeInfo|-10052:SoldierBuff|-10051:ActivityGDS|-10050:Milkout|-10049:StorySetInfoResp|-10048:ActivityHistoryStoryChapter|-10047:AssistAddBuildNotify|-10046:GmClearAllActivityLevelsNotify|-10045:GmClear" +
    "AllActivityAvgNotify|-10044:CardInfo|-10043:GmImportCharGemsNotify|-10042:String|-10040:GmClearAllCharGemInstance|-10039:NPCAffinityInfo|-10038:TowerChangeData|-10037:Quests|-10036:ScoreBossInfo|-10035:Nil|-10034:GmCharUpNotify|-10033:GmTowerGrowthNodesNotify|-10032:GmHarmonySkillNotify|-10031:GmStory|-10030:GmStory|-10029:InfinityTowerLevelInfo|-10028:GmAllInfinityTowerInfos|-10027:GmClearAllEqui" +
    "pmentInstance|-10026:StarTowerBuildInfo|-10025:String|-10024:StarTowerRoomCase|-10023:STAddTeamExpNtf|-10022:StarTowerInfo|-10021:GmSTClearAllStarTower|-10020:ChangeInfo|-10019:CharAffinity|-10018:GmClearAllSkillInstance|-10017:Disc|-10016:GmClearAllTravelerDue|-10015:GmClearAllRegionBossLevel|-10014:WeekBossLevels|-10013:GmClearAllDailyInstance|-10012:AgentInfos|-10011:StarTowerSubNoteSkillInfo|-" +
    "10010:VampireTalentDetailResp|-10009:UI32|-10008:GmClearAllVampireSurvivor|-10007:RegionBossLevel|-10006:Chars|-10005:GmWorldClass|-10004:Char|-10003:Char|-10001:ChangeInfo|-3:Error|-2:Nil|-1:SudoCommand|1:IKEReq|2:IKEResp|3:Error|4:LoginReq|5:LoginResp|6:Error|1001:Nil|1002:PlayerInfo|1003:Error|1004:PlayerReg|1005:Error|1006:PlayerNameEditReq|1007:PlayerNameEditResp|1008:Error|1009:PlayerHeadIco" +
    "nSetReq|1010:Nil|1011:Error|1012:Ping|1013:Pong|1014:Error|1015:NewbieInfo|1016:Nil|1017:Error|1018:Nil|1019:PlayerDestroy|1020:Error|1021:PlayerBoardSetReq|1022:Nil|1023:Error|1024:PlayerWorldClassRewardReq|1025:ChangeInfo|1026:Error|1027:PlayerSignatureEditReq|1028:Nil|1029:Error|1030:PlayerTitleEditReq|1031:Nil|1032:Error|1033:PlayerCharsShowReq|1034:Nil|1035:Error|1036:PlayerSkinShowReq|1037:N" +
    "il|1038:Error|1039:Nil|1040:Nil|1041:Error|1042:PlayerSurveyReq|1043:PlayerSurveyResp|1044:Error|1045:Nil|1046:Nil|1047:Error|1048:PlayerHonorEditReq|1049:Nil|1050:Error|1051:Nil|1052:ChangeInfo|1053:Error|1054:I64|1055:Nil|1056:Error|1057:Nil|1058:PlayerHeadIconInfoResp|1059:Error|1101:ItemUseReq|1102:ChangeInfo|1103:Error|1104:UI32|1105:ChangeInfo|1106:Error|1107:ItemProductReq|1108:ChangeInfo|1" +
    "109:Error|1110:Nil|1111:ChangeInfo|1112:Error|1113:Nil|1114:ChangeInfo|1115:Error|1116:ItemGrowthReq|1117:ChangeInfo|1118:Error|1119:Nil|1120:ChangeInfo|1121:Error|1201:Nil|1202:FriendListGetResp|1203:Error|1204:FriendUIdSearchReq|1205:FriendUIdSearchResp|1206:Error|1207:FriendNameSearchReq|1208:FriendNameSearchResp|1209:Error|1210:FriendAddReq|1211:Nil|1212:Error|1213:FriendAddAgreeReq|1214:Frien" +
    "dAddAgreeResp|1215:Error|1216:Nil|1217:FriendAllAgreeResp|1218:Error|1219:FriendDeleteReq|1220:Nil|1221:Error|1222:FriendInvitesDeleteReq|1223:Nil|1224:Error|1225:FriendStarSetReq|1226:Nil|1227:Error|1228:FriendReceiveEnergyReq|1229:FriendReceiveEnergyResp|1230:Error|1231:FriendSendEnergyReq|1232:FriendSendEnergyResp|1233:Error|1234:Nil|1235:FriendRecommendationGetResp|1236:Error|1301:Nil|1302:Tow" +
    "erGrowthDetailResp|1303:Error|1304:UI32|1305:ChangeInfo|1306:Error|1307:UI32|1308:TowerGrowthGroupNodeUnlockResp|1309:Error|1401:MilkoutSettleReq|1402:ChangeInfo|1403:Error|1501:ActivityGDSSettleReq|1502:ChangeInfo|1503:Error|1601:ActivitySoldierQuestRewardReceiveReq|1602:ChangeInfo|1603:Error|2001:PlayerFormationReq|2002:Nil|2003:Error|2301:CharUpgradeReq|2302:CharUpgradeResp|2303:Error|2304:UI32" +
    "|2305:ChangeInfo|2306:Error|2307:CharSkillUpgradeReq|2308:ChangeInfo|2309:Error|2313:CharAdvanceRewardReceiveReq|2314:CharAdvanceRewardReceiveResp|2315:Error|2316:CharSkinSetReq|2317:Nil|2318:Error|2322:CharAffinityQuestRewardReceiveReq|2323:CharAffinityQuestRewardReceiveResp|2324:Error|2325:UI32|2326:ChangeInfo|2327:Error|2328:CharAffinityGiftSendReq|2329:CharAffinityGiftSendResp|2330:Error|2401:" +
    "CharDatingLandmarkSelectReq|2402:CharDatingLandmarkSelectResp|2403:Error|2404:CharDatingGiftSendReq|2405:CharDatingGiftSendResp|2406:Error|2407:CharDatingEventRewardReceiveReq|2408:ChangeInfo|2409:Error|2410:CharArchiveRewardReceiveReq|2411:ChangeInfo|2412:Error|2413:CharDatingBranchASelectReq|2414:CharDatingBranchASelectResp|2415:Error|2416:CharDatingBranchBSelectReq|2417:CharDatingBranchBSelectR" +
    "esp|2418:Error|2501:CharGemGenerateReq|2502:CharGemGenerateResp|2503:Error|2504:CharGemRefreshReq|2505:CharGemRefreshResp|2506:Error|2507:CharGemReplaceAttributeReq|2508:Nil|2509:Error|2510:CharGemUpdateGemLockStatusReq|2511:Nil|2512:Error|2513:CharGemUsePresetReq|2514:Nil|2515:Error|2516:CharGemRenamePresetReq|2517:Nil|2518:Error|2519:CharGemEquipGemReq|2520:Nil|2521:Error|2522:CharGemOverlockRev" +
    "ertReq|2523:ChangeInfo|2524:Error|2525:CharGemOverlockReq|2526:ChangeInfo|2527:Error|2601:UI32|2602:Nil|2603:Error|3119:DiscStrengthenReq|3120:DiscStrengthenResp|3121:Error|3122:DiscPromoteReq|3123:DiscPromoteResp|3124:Error|3125:DiscLimitBreakReq|3126:DiscLimitBreakResp|3127:Error|3128:DiscReadRewardReceiveReq|3129:ChangeInfo|3130:Error|3131:Nil|3132:DiscAllLimitBreakResp|3133:Error|3301:AgentApp" +
    "lyReq|3302:AgentApplyResp|3303:Error|3304:AgentGiveUpReq|3305:AgentGiveUpResp|3306:Error|3307:AgentRewardReceiveReq|3308:AgentRewardReceiveResp|3309:Error|4201:UI32|4202:TourGuideQuestRewardResp|4203:Error|4204:UI32|4205:ChangeInfo|4206:Error|4207:DictRewardReq|4208:ChangeInfo|4209:Error|4210:UI32|4211:ChangeInfo|4212:Error|4213:Nil|4214:QuestDailyActiveRewardReceiveResp|4215:Error|4216:Nil|4217:T" +
    "ourGuideQuestGroupRewardResp|4218:Error|4219:UI32|4220:ChangeInfo|4221:Error|4222:Nil|4223:QuestWeeklyActiveRewardReceiveResp|4224:Error|4225:AssistQuestReceiveReq|4226:ChangeInfo|4227:Error|4228:UI32|4229:AssistGroupRewardResp|4230:Error|4231:UI32V|4232:QuestDormRewardReceiveSucceedAck|4233:Error|4301:ActivityTaskRewardReceiveReq|4302:ChangeInfo|4303:Error|4304:UI32|4305:ChangeInfo|4306:Error|440" +
    "1:AchievementRewardReq|4402:ChangeInfo|4403:Error|4404:Nil|4405:Achievements|4406:Error|4501:Nil|4502:InfinityTowerInfoResp|4503:Error|4504:InfinityTowerApplyReq|4505:Nil|4506:Error|4507:InfinityTowerSettleReq|4508:InfinityTowerSettleResp|4509:Error|4510:Nil|4511:InfinityTowerDailyRewardReceiveResp|4512:Error|4513:UI32|4514:InfinityTowerPlotRewardReceiveResp|4515:Error|4601:StarTowerApplyReq|4602:" +
    "StarTowerApplyResp|4603:Error|4607:StarTowerInteractReq|4608:StarTowerInteractResp|4609:Error|4610:Nil|4611:StarTowerInfo|4612:Error|4613:Nil|4614:StarTowerGiveUpResp|4615:Error|4701:StarTowerBuildWhetherSaveReq|4702:StarTowerBuildWhetherSaveResp|4703:Error|4704:Nil|4705:StarTowerBuildBriefListGetResp|4706:Error|4707:StarTowerBuildDetailGetReq|4708:StarTowerBuildDetailGetResp|4709:Error|4710:StarT" +
    "owerBuildDeleteReq|4711:StarTowerBuildDeleteResp|4712:Error|4713:StarTowerBuildNameSetReq|4714:Nil|4715:Error|4716:StarTowerBuildLockUnlockReq|4717:Nil|4718:Error|4719:StarTowerBuildPreferenceSetReq|4720:Nil|4721:Error|4722:Nil|4723:PotentialPreselectionList|4724:Error|4725:PotentialPreselectionImportReq|4726:PotentialPreselection|4727:Error|4728:PotentialPreselectionNameSetReq|4729:Nil|4730:Error" +
    "|4731:PotentialPreselectionPreferenceSetReq|4732:Nil|4733:Error|4734:PotentialPreselectionUpdateReq|4735:PotentialPreselection|4736:Error|4737:PotentialPreselectionDeleteReq|4738:Nil|4739:Error|4740:UI32|4741:TowerVitaEnergyBuyResp|4742:Error|4743:Nil|4744:TowerVitaProjectListResp|4745:Error|4746:TowerVitaProjectUpdateRep|4747:Nil|4748:Error|4749:TowerVitaProjectNameUpdateRep|4750:Nil|4751:Error|4" +
    "752:TowerVitaProjectSetRep|4753:Nil|4754:Error|4755:StarTowerBuildPotentialModifyReq|4756:StarTowerBuildPotentialModifyResp|4757:Error|4758:StarTowerBuildNoteModifyReq|4759:StarTowerBuildNoteModifyResp|4760:Error|4801:Nil|4802:BuildConvertDetailListGetResp|4803:Error|4804:BuildConvertSubmitReq|4805:BuildConvertSubmitResp|4806:Error|4807:UI32|4808:BuildConvertGroupRewardReceiveResp|4809:Error|4901:" +
    "Nil|4902:StarTowerBookPotentialBriefListResp|4903:Error|4904:UI32|4905:StarTowerBookPotentialGetResp|4906:Error|4907:UI32|4908:StarTowerBookPotentialRewardReceiveResp|4909:Error|4913:UI32|4914:StarTowerBookEventRewardReceiveResp|4915:Error|4916:Nil|4917:NPCAffinityBookGetResp|4918:Error|4919:UI32|4920:NPCAffinityPlotRewardReceiveResp|4921:Error|5010:ResidentShopGetReq|5011:ResidentShopGetResp|5012" +
    ":Error|5013:ResidentShopPurchaseReq|5014:ResidentShopPurchaseResp|5015:Error|5101:Nil|5102:MallGemList|5103:Error|5104:String|5105:OrderInfo|5106:Error|5107:String|5108:String|5109:Error|5110:String|5111:CollectResp|5112:CollectResp|5113:Nil|5114:MallMonthlyCardList|5115:Error|5116:String|5117:OrderInfo|5118:Error|5119:Nil|5120:MallPackageList|5121:Error|5122:String|5123:MallPackageOrder|5124:Erro" +
    "r|5125:Nil|5126:MallShopProductList|5127:Error|5128:MallShopOrderReq|5129:ChangeInfo|5130:Error|5131:Nil|5132:MallActivityList|5133:Error|5134:String|5135:OrderInfo|5136:Error|5201:Nil|5202:TraceHuntInfo|5203:Error|5204:TraceHuntApplyReq|5205:Nil|5206:Error|5207:TraceHuntSettleReq|5208:TraceHuntSettleResp|5209:Error|5210:Nil|5211:TraceHuntRecommendResp|5212:Error|5213:Nil|5214:TraceHuntBossRewardR" +
    "eceiveResp|5215:Error|5216:I32|5217:TraceHuntTraceResp|5218:Error|5301:SoldierApplyReq|5302:SoldierApplyResp|5303:Error|5304:Nil|5305:SoldierInfo|5306:Error|5307:SoldierInteractReq|5308:SoldierInteractResp|5309:Error|5310:Nil|5311:SoldierSettleDataResp|5312:Error|5313:Nil|5314:Nil|5315:Error|5316:SoldierPartnerTraceReq|5317:Nil|5318:Error|5319:UI32|5320:SoldierSeasonInfo|5321:Error|5322:UI32|5323:" +
    "SoldierSeasonRewardReceiveResp|5324:Error|5325:SoldierLearnReq|5326:Nil|5327:Error|5401:UI32|5402:Bytes|5403:Error|5404:UI32|5405:ChangeInfo|5406:Error|5407:String|5408:Nil|5409:Error|5410:String|5411:Nil|5412:Error|5413:Nil|5414:SoldierBattleReportFavoriteList|5415:Error|5416:Nil|5417:SoldierBattleReportRecentList|5418:Error|6001:GachaSpinReq|6002:GachaSpinResp|6003:Error|6004:Nil|6005:GachaInfor" +
    "mationResp|6006:Error|6007:UI32|6008:GachaHistories|6009:Error|6010:UI32|6011:ChangeInfo|6012:Error|6013:UI32|6014:GachaNewbieSpinResp|6015:Error|6016:GachaNewbieSaveReq|6017:Nil|6018:Error|6019:GachaNewbieObtainReq|6020:ChangeInfo|6021:Error|6022:Nil|6023:GachaNewbieInfoResp|6024:Error|6025:GachaSpinSyncResp|6026:UI32|6027:ChangeInfo|6028:Error|6101:Nil|6102:TowerBookFateCardDetailResp|6103:Error" +
    "|6104:TowerBookFateCardRewardReq|6105:ChangeInfo|6106:Error|6201:JointDrillApplyReq|6202:JointDrillApplyResp|6203:Error|6204:JointDrillContinueReq|6205:Nil|6206:Error|6207:JointDrillSyncReq|6208:Nil|6209:Error|6210:JointDrillGiveUpReq|6211:JointDrillSettle|6212:Error|6213:Nil|6214:Nil|6215:Error|6216:JointDrillSettleReq|6217:JointDrillSettle|6218:Error|6219:Nil|6220:JointDrillSettle|6221:Error|622" +
    "2:JointDrillSweepReq|6223:JointDrillSweepResp|6224:Error|6225:Nil|6226:JointDrillRankInfo|6227:Error|6228:Nil|6229:ChangeInfo|6230:Error|6301:JointDrill2ApplyReq|6302:JointDrill2ApplyResp|6303:Error|6304:JointDrill2ContinueReq|6305:Nil|6306:Error|6307:JointDrill2SyncReq|6308:Nil|6309:Error|6310:JointDrill2GiveUpReq|6311:JointDrillSettle|6312:Error|6313:Nil|6314:Nil|6315:Error|6316:JointDrill2Settl" +
    "eReq|6317:JointDrillSettle|6318:Error|6319:Nil|6320:JointDrillSettle|6321:Error|7013:UI32|7014:ChangeInfo|7015:Error|7016:DailyInstanceApplyReq|7017:Nil|7018:Error|7019:DailyInstanceSettleReq|7020:DailyInstanceSettleResp|7021:Error|7022:DailyInstanceRaidReq|7023:DailyInstanceRaidResp|7024:Error|7028:CharGemInstanceApplyReq|7029:ChangeInfo|7030:Error|7031:CharGemInstanceSettleReq|7032:CharGemInstan" +
    "ceSettleResp|7033:Error|7034:CharGemInstanceSweepReq|7035:CharGemInstanceSweepResp|7036:Error|7101:RegionBossLevelApplyReq|7102:ChangeInfo|7103:Error|7104:RegionBossLevelSettleReq|7105:RegionBossLevelSettleResp|7106:Error|7107:RegionBossLevelSweepReq|7108:RegionBossLevelSweepResp|7109:Error|7201:TravelerDuelLevelApplyReq|7202:Nil|7203:Error|7204:TravelerDuelLevelSettleReq|7205:TravelerDuelLevelSet" +
    "tleResp|7206:Error|7207:Nil|7208:TravelerDuelInfo|7209:Error|7210:TravelerDuelQuestRewardReceiveReq|7211:TravelerDuelQuestRewardReceiveResp|7212:Error|7213:Nil|7214:TravelerDuelRankInfo|7215:Error|7216:TravelerDuelBattleSamples|7217:RankChange|7218:Error|7301:StoryApplyReq|7302:Nil|7303:Error|7304:StorySettleReq|7305:ChangeInfo|7306:Error|7401:SkillInstanceApplyReq|7402:ChangeInfo|7403:Error|7404:" +
    "SkillInstanceSettleReq|7405:SkillInstanceSettleResp|7406:Error|7407:SkillInstanceSweepReq|7408:SkillInstanceSweepResp|7409:Error|7410:WeekBossApplyReq|7411:Nil|7412:Error|7413:WeekBossSettleReq|7414:WeekBossLevelSettleResp|7415:Error|7501:UI32|7502:Nil|7503:Error|7504:UI32|7505:ChangeInfo|7506:Error|7601:Nil|7602:StorySetInfoResp|7603:Error|7604:StorySetRewardReceiveReq|7605:ChangeInfo|7606:Error|" +
    "8001:UI32|8002:EnergyBuyResp|8003:Error|8004:UI32|8005:ChangeInfo|8006:Error|8007:Nil|8008:Energy|8009:Error|8101:Events|8102:Nil|8103:Error|8201:VampireSurvivorApplyReq|8202:VampireSurvivorApplyResp|8203:Error|8204:VampireSurvivorAreaChangeReq|8205:Nil|8206:Error|8207:VampireSurvivorSettleReq|8208:VampireSurvivorSettleResp|8209:Error|8210:VampireSurvivorRewardSelectReq|8211:VampireSurvivorRewardS" +
    "electResp|8212:Error|8213:VampireSurvivorRewardChestReq|8214:VampireSurvivorRewardChestResp|8215:Error|8216:VampireSurvivorQuestRewardReceiveReq|8217:ChangeInfo|8218:Error|8222:VampireSurvivorRewardSelectReq|8223:VampireSurvivorRewardSelectResp|8224:Error|8225:Nil|8226:Nil|8227:Error|8301:Nil|8302:VampireTalentDetailResp|8303:Error|8304:Nil|8305:Nil|8306:Error|8307:UI32|8308:Nil|8309:Error|8310:Ni" +
    "l|8311:Nil|8312:Error|8313:Nil|8314:VampireSurvivorInfoResp|8315:Error|8316:ActivityStoryApplyReq|8317:Nil|8318:Error|8319:ActivityStorySettleReq|8320:ChangeInfo|8321:Error|8322:ActivityThrowGiftSettleReq|8323:ChangeInfo|8324:Error|8325:LastRead|8326:Nil|8327:Error|8328:ActivityHistoryStoryApplyReq|8329:Nil|8330:Error|8331:ActivityHistoryStorySettleReq|8332:ChangeInfo|8333:Error|8401:ActivityPengu" +
    "inCardSettleReq|8402:ChangeInfo|8403:Error|8404:ActivityPenguinCardQuestReceiveReq|8405:ChangeInfo|8406:Error|8407:ActivityDoubleQuestRewardReq|8408:ChangeInfo|8409:Error|8411:ActivityIceCreamLevelSettleReq|8412:ActivityIceCreamLevelSettleSucceed|8413:Error|8416:ActivityPenguinCardEndlessLevelSaveReq|8417:Nil|8418:Error|8419:Nil|8420:GuideMissionInfo|8421:Error|8422:GuideMissionQuestRewardReceiveR" +
    "eq|8423:ChangeInfo|8424:Error|8430:ActivityMathParkourLevelSettleReq|8431:ActivityMathParkourLevelSettleSucceed|8432:Error|8501:Nil|8502:ActivityReturneeInfoResp|8503:Error|8504:Nil|8505:ChangeInfo|8506:Error|8507:UI32|8508:ChangeInfo|8509:Error|8510:Nil|8511:Nil|8512:Error|8513:UI32|8514:ChangeInfo|8515:Error|8516:Nil|8517:ChangeInfo|8518:Error|8519:Nil|8520:ChangeInfo|8521:Error|8522:String|8523" +
    ":OrderInfo|8524:Error|8525:String|8526:OrderInfo|8527:Error|8601:ActivityArchiveStoryApplyReq|8602:Nil|8603:Error|8604:ActivityArchiveStorySettleReq|8605:ChangeInfo|8606:Error|8607:UI32|8608:ActivityHistoryStoryChapter|8609:Error|8610:UI32|8611:ChangeInfo|8612:Error|8613:ActivityArchiveStoryChapterPassReq|8614:Nil|8615:Error|9001:Nil|9002:Mails|9003:Error|9004:MailRequest|9005:UI32|9006:Error|9007" +
    ":MailRequest|9008:MailRecvResp|9009:Error|9010:MailRequest|9011:MailRemoveResp|9012:Error|9013:MailPinRequest|9014:MailPinRequest|9015:Error|9101:Nil|9102:ActivityResp|9103:Error|9104:ActivityPeriodicRewardReq|9105:ChangeInfo|9106:Error|9107:UI32|9108:ChangeInfo|9109:Error|9110:UI32|9111:ChangeInfo|9112:Error|9113:UI32|9114:ChangeInfo|9115:Error|9116:ActivityTowerDefenseQuestReceiveReq|9117:Change" +
    "Info|9118:Error|9119:ActivityTowerDefenseLevelApplyReq|9120:Nil|9121:Error|9122:ActivityTowerDefenseLevelSettleReq|9123:ChangeInfo|9124:Error|9125:ActivityTrekkerVersusApplyReq|9126:Nil|9127:Error|9128:ActivityTrekkerVersusSettleReq|9129:ActivityTrekkerVersusSettleResp|9130:Error|9131:UI32|9132:ActivityTrekkerVersusRewardReceiveResp|9133:Error|9134:UI32|9135:TrekkerVersusShow|9136:Error|9137:UI32|" +
    "9138:ActivityTrekkerVersusIdleRewardReceiveResp|9139:Error|9140:ActivityTrekkerVersusRankBoostReq|9141:ActivityTrekkerVersusRankBoostResp|9142:Error|9143:ActivityTrekkerVersusScheduleRewardReceiveReq|9144:ActivityTrekkerVersusScheduleRewardReceiveResp|9145:Error|9146:UI32|9147:ChangeInfo|9148:Error|9201:Nil|9202:PhoneContactsInfoResp|9203:Error|9204:PhoneContactsReportReq|9205:ChangeInfo|9206:Erro" +
    "r|9207:UI32|9208:Nil|9209:Error|9210:ActivityShareRewardReq|9211:ChangeInfo|9212:Error|9301:UI32|9302:TalentUnlockResp|9303:Error|9304:TalentResetReq|9305:ChangeInfo|9306:Error|9307:UI32|9308:TalentNodeResetResp|9309:Error|9310:TalentBackgroundSetReq|9311:Nil|9312:Error|9313:UI32|9314:TalentGroupUnlockResp|9315:Error|9401:ActivityTrialRewardReceiveReq|9402:ChangeInfo|9403:Error|9501:UI32|9502:Chan" +
    "geInfo|9503:Error|9510:Nil|9511:DormInfoListResp|9512:Error|9513:Nil|9514:DormFurniturePresetListResp|9515:Error|9516:Nil|9517:DormBagListResp|9518:Error|9519:UI32|9520:Nil|9521:Error|9522:DormFurnitureSaveReq|9523:I64|9524:Error|9525:StringV|9526:Nil|9527:Error|9528:DormInvitationRoleReq|9529:Nil|9530:Error|9531:DormRewardReceiveReq|9532:ChangeInfo|9533:Error|9534:DormRoleInteractionReq|9535:Dorm" +
    "RoleInteractionResp|9536:Error|9537:DormAffinityGiftSendReq|9538:DormAffinityGiftSendResp|9539:Error|9540:Nil|9541:DormFriendListResp|9542:Error|9543:DormFriendVisitReq|9544:DormFriendVisitResp|9545:Error|9547:DormLayoutRewardReceiveReq|9548:ChangeInfo|9549:Error|9550:DormRoomBGMReq|9551:Nil|9552:Error|9553:DormFriendLikeReq|9554:Nil|9555:Error|9556:StringV|9557:Nil|9558:Error|9559:UI32V|9560:Nil|" +
    "9561:Error|9562:DormAchievementRewardReceiveReq|9563:AchievementComplete|9564:Error|9565:UI32|9566:ChangeInfo|9567:Error|9568:Nil|9569:DormChangeDataResp|9570:Error|9571:NewbieInfo|9572:Nil|9573:Error|9601:ActivityLevelsApplyReq|9602:ChangeInfo|9603:Error|9604:ActivityLevelsSettleReq|9605:ActivityLevelsSettleResp|9606:Error|9607:ActivityLevelsSweepReq|9608:ActivityLevelsSweepResp|9609:Error|9701:A" +
    "ctivityAvgRewardReceiveReq|9702:ChangeInfo|9703:Error|9751:ActivityShopPurchaseReq|9752:ActivityShopPurchaseResp|9753:Error|9801:Nil|9802:BattlePassInfo|9803:Error|9804:BattlePassRewardReceiveReq|9805:BattlePassRewardReceiveResp|9806:Error|9807:UI32V|9808:BattlePassLevelBuyResp|9809:Error|9810:BattlePassOrderReq|9811:OrderInfo|9812:Error|9813:String|9814:BattlePassOrderCollectResp|9815:CollectResp" +
    "|9816:UI32|9817:BattlePassQuestRewardResp|9818:Error|9901:String|9902:RedeemCodeResp|9903:Error|10000:Error|10001:Nil|10002:MailState|10003:Error|10004:Error|10005:Error|10006:Quest|10007:ChangeInfo|10008:NewAgent|10009:WorldClassUpdate|10010:FriendEnergyState|10011:SigninRewardUpdate|10012:FriendState|10013:OrderStateChange|10014:ChangeInfo|10015:StarTowerBookPotentialChange|10016:StarTowerBookEv" +
    "entChange|10017:BattlePassState|10018:WorldClassRewardState|10019:CharAdvanceRewardState|10020:Achievement|10021:AchievementState|10022:Skin|10023:SkinChange|10024:HandbookInfo|10025:MonthlyCardRewards|10026:QuestState|10027:MallPackageState|10028:Dictionary|10029:Activity|10030:ActivityQuest|10031:CharAffinityRewardState|10032:Nil|10033:UI32|10034:UI32|10035:ChangeInfo|10036:ActivityLogin|10037:T" +
    "owerBookFateCardCollectNotify|10038:TowerBookFateCardRewardChangeNotify|10039:ChangeInfo|10040:HonorChangeNotify|10041:ChangeInfo|10042:ChangeInfo|10043:ChangeInfo|10044:NoticeChangeNotify|10045:ActivityState|10046:ChangeInfo|10047:UI64|10048:PlayerHeadIconChangeNotify|10049:ActivityMiningEnterLayerNotify|10050:UI32|10051:UI32|10052:OrderCollected|10053:ChangeInfo|10054:ItemTpl|10055:MilkoutCharac" +
    "terUnlockNotify|10056:ActivityDoubleRewardTimesNotify|10057:Nil|10058:TraceHuntState|10060:TraceHuntItem|10061:Nil|10062:ActivityReturneeState|10063:Quest|10064:DormRoomUnlock|10065:GuideMissionState|10066:ActivityMallLogin|10067:AchievementInfo|11001:ActivityMiningApplyReq|11002:ActivityMiningApplyResp|11003:Error|11004:ActivityMiningDigReq|11005:ActivityMiningDigResp|11006:Error|11007:ActivityMi" +
    "ningMoveToNextLayerReq|11008:ActivityMiningMoveToNextLayerResp|11009:Error|11010:ActivityMiningStoryRewardReceiveReq|11011:ChangeInfo|11012:Error|11013:ActivityMiningQuestRewardReceiveReq|11014:ChangeInfo|11015:Error|11101:ScoreBossApplyReq|11102:Nil|11103:Error|11104:ScoreBossSettleReq|11105:ScoreBossSettleResp|11106:Error|11107:Nil|11108:ScoreBossRankInfo|11109:Error|11110:ScoreBossStarRewardRec" +
    "eiveReq|11111:ChangeInfo|11112:Error|11113:Nil|11114:ScoreBossInfo|11115:Error|11201:ActivityCookieSettleReq|11202:ChangeInfo|11203:Error|11204:ActivityCookieQuestRewardReceiveReq|11205:ChangeInfo|11206:Error";

static string SS_SCHEMA_STR =
    "Any|1:type_url:s,2:value:b,2047:NextPackage:b\nNil|2047:NextPackage:b\nI32|1:Value:i,2047:NextPackage:b\nI64|1:Value:l,2047:NextPackage:b\nUI32|1:Value:u,2047:NextPackage:b\nUI32s|1:Values:ru,2047:NextPackage:b\nUI64|1:Value:u,2047:NextPackage:b\nString|1:Value:s,2047:NextPackage:b\nI32V|1:Value:i,2:Version:u,2047:NextPackage:b\nUI32V|1:Value:u,2:Version:u,2047:NextPackage:b\nUI64V|1:Value:u,2:Version:u,204" +
    "7:NextPackage:b\nStringV|1:Value:s,2:Version:u,2047:NextPackage:b\nBytes|1:Value:b,2047:NextPackage:b\nBytesV|1:Value:b,2:Version:u,2047:NextPackage:b\nBoolean|1:Ok:u,2047:NextPackage:b\nError|1:Code:u,2:Arguments:rs,3:TraceId:u,4:Action:i,2047:NextPackage:b\nAccInfo|1:Id:u,2:NickName:s,3:Hashtag:u,4:HeadIcon:u,5:Gender:u,6:Signature:s,7:TitlePrefix:u,8:TitleSuffix:u,9:Chars:r>CharShow,10:SkinId:u,14:Ne" +
    "wbies:r>NewbieInfo,15:CreateTime:l,2047:NextPackage:b\nNewbieInfo|1:GroupId:u,2:StepId:i,2047:NextPackage:b\nQuestProgress|1:Cur:u,2:Max:u,2047:NextPackage:b\nQuest|1:Id:u,2:Status:u,3:Expire:l,4:Type:u,15:Progress:r>QuestProgress,2047:NextPackage:b\nQuests|1:List:r>Quest,2047:NextPackage:b\nAchievement|1:Id:u,2:Status:u,3:Completed:l,4:Progress:r>QuestProgress,2047:NextPackage:b\nAchievements|1:List:r>" +
    "Achievement,2047:NextPackage:b\nDictionary|1:TabId:u,2:Index:u,3:Status:u,2047:NextPackage:b\nDictionaries|1:List:r>Dictionary,2047:NextPackage:b\nEvent|1:Id:u,2:Data:ru,2047:NextPackage:b\nEvents|1:List:r>Event,2047:NextPackage:b\nMail|1:Id:u,2:Subject:s,3:Desc:s,4:TemplateId:u,5:Author:s,6:Time:l,7:Deadline:l,8:Read:u,9:Recv:u,10:Attachments:r>ItemTpl,11:Flag:u,12:SubjectArgs:rs,13:DescArgs:rs,14:Sur" +
    "veyId:l,15:Pin:u,2047:NextPackage:b\nMails|1:List:r>Mail,2047:NextPackage:b\nMailRequest|1:Id:u,2:Flag:u,2047:NextPackage:b\nMailState|1:New:u,2:Revoke:u,2047:NextPackage:b\nAchievementState|1:New:u,2047:NextPackage:b\nFriendState|1:Id:u,2:Action:u,2047:NextPackage:b\nBattlePassState|1:State:i,2047:NextPackage:b\nCharAdvanceRewardState|1:CharId:u,2:Flag:b,2047:NextPackage:b\nWorldClassRewardState|1:Flag:b" +
    ",2047:NextPackage:b\nFriendEnergyState|1:State:u,2047:NextPackage:b\nCharAffinityRewardState|1:CharId:u,2:QuestIds:ru,2047:NextPackage:b\nStarTowerState|1:Id:u,2:ReConnection:u,3:BuildId:u,4:CharIds:ru,6:Floor:u,15:Sweep:u,2047:NextPackage:b\nStarTowerBookState|1:CharIds:ru,2:EventIds:ru,3:Bundles:ru,2047:NextPackage:b\nActivityReturneeState|1:Type:u,2:State:u,2047:NextPackage:b\nSoldierState|1:CurGrade" +
    "ChallengeId:u,2:Stage:u,3:NodeIndex:u,4:CurSeasonId:u,2047:NextPackage:b\nStateInfo|1:Mail:>MailState,2:InfinityTower:u,3:Friend:u,4:BattlePass:>BattlePassState,5:WorldClassReward:>WorldClassRewardState,6:CharAdvanceRewards:r>CharAdvanceRewardState,7:FriendEnergy:>FriendEnergyState,8:CharAffinityRewards:r>CharAffinityRewardState,9:NpcAffinityReward:u,10:MallPackage:>MallPackageState,11:VampireSurvi" +
    "vorId:u,12:Soldier:>SoldierState,15:Achievement:>AchievementState,16:TravelerDuelQuest:>QuestState,17:TravelerDuelIdleReward:l,18:StarTower:>StarTowerState,19:StarTowerBook:>StarTowerBookState,20:ScoreBoss:>ScoreBossState,21:Activities:r>ActivityState,22:StorySet:u,23:TraceHunt:>TraceHuntState,24:ActivityReturnees:r>ActivityReturneeState,25:DormStateFlag:u,26:GuideMission:>GuideMissionState,2047:N" +
    "extPackage:b\nItemTpl|1:Tid:u,2:Qty:i,2047:NextPackage:b\nItemTpls|1:Items:r>ItemTpl,2047:NextPackage:b\nItem|1:Id:u,2:Tid:u,3:Qty:i,4:Expire:l,2047:NextPackage:b\nRes|1:Tid:u,2:Qty:i,2047:NextPackage:b\nTitle|1:TitleId:u,2047:NextPackage:b\nChar|1:Tid:u,2:Exp:u,3:DatingLandmarkIds:ru,4:DatingEventIds:ru,5:DatingEventRewardIds:ru,6:EquipmentIds:ru,9:Level:u,10:SkillLvs:ru,12:Skin:u,13:AffinityLevel:u,14" +
    ":AffinityExp:u,15:Advance:u,16:Plots:ru,17:AffinityQuests:>Quests,19:TalentNodes:b,20:ArchiveRewardIds:ru,21:TalentBackground:u,22:CharGemSlots:r>CharGemSlot,23:CharGemPresets:>CharGemPresets,31:IsFavorite:u,127:CreateTime:l,2047:NextPackage:b\nEnergy|1:Primary:u,2:Secondary:u,3:IsPrimary:u,4:UpdateTime:l,5:NextDuration:l,2047:NextPackage:b\nWorldClass|1:AddClass:u,2:ExpChange:i,2047:NextPackage:b\nE" +
    "quipment|1:Info:>EquipmentInfo,2:Qty:i,2047:NextPackage:b\nDisc|1:Id:u,2:Level:u,3:Exp:u,4:Phase:u,5:Star:u,6:Read:u,7:Avg:u,15:CreateTime:l,2047:NextPackage:b\nTransform|1:Src:r>ItemTpl,2:Dst:r>ItemTpl,2047:NextPackage:b\nHeadIcon|1:Tid:u,2047:NextPackage:b\nDormItem|1:Tid:u,2:Qty:i,3:IsFirst:u,2047:NextPackage:b\nAcqInfo|1:Tid:u,2:Begin:u,3:Count:u,2047:NextPackage:b\nAcquire|1:List:r>AcqInfo,2047:Nex" +
    "tPackage:b\nHonor|1:NewId:u,2:Level:u,2047:NextPackage:b\nChangeInfo|1:Props:r>Any,2047:NextPackage:b\nFormationInfo|1:Number:u,2:CharIds:ru,3:DiscIds:ru,4:PreselectionId:u,2047:NextPackage:b\nFormationRecord|1:GroupId:u,2:Number:u,2047:NextPackage:b\nTowerFormation|1:Info:r>FormationInfo,2:Record:r>FormationRecord,2047:NextPackage:b\nStoryChoice|1:Group:u,2:Value:u,2047:NextPackage:b\nStory|1:Idx:u,2:Ma" +
    "jor:r>StoryChoice,3:Personality:r>StoryChoice,2047:NextPackage:b\nStoryInfo|1:Evidences:ru,2:Stories:r>Story,3:Build:>UseBuild,2047:NextPackage:b\nRoomRestored|1:RoomId:u,2:Change:>ChangeInfo,2047:NextPackage:b\nDropPkg|1:Drops:r>ItemTpl,2047:NextPackage:b\nMonsterDrop|1:MonsterIndex:u,2:DropPkgs:r>DropPkg,2047:NextPackage:b\nWorldClassUpdate|1:Cur:u,2:Change:>ChangeInfo,2047:NextPackage:b\nItemInfo|1:I" +
    "d:u,2:Tid:u,3:Qty:u,2047:NextPackage:b\nRegionBossLevel|1:Id:u,2:Star:u,3:First:u,4:ThreeStar:u,5:Build:>UseBuild,2047:NextPackage:b\nFriend|1:Id:u,2:NickName:s,3:Hashtag:u,4:HeadIcon:u,5:LastLoginTime:l,6:WorldClass:u,7:TitlePrefix:u,8:TitleSuffix:u,9:Signature:s,10:CharShows:r>CharShow,15:Honors:r>HonorInfo,16:DormOutInfo:>DormOutInfo,17:DormLikeNum:u,2047:NextPackage:b\nCharShow|1:CharId:u,2:Level" +
    ":u,3:Skin:u,2047:NextPackage:b\nFriendDetail|1:Base:>Friend,2:Star:u,3:SendEnergy:u,4:GetEnergy:u,2047:NextPackage:b\nBoughtGoods|1:Id:u,2:Number:u,2047:NextPackage:b\nResidentShop|1:Id:u,2:RefreshTime:l,3:Infos:r>BoughtGoods,2047:NextPackage:b\nHandbookInfo|1:Type:u,2:Data:b,2047:NextPackage:b\nQuestState|1:Type:u,2:New:u,2047:NextPackage:b\nMallPackageState|1:New:u,2047:NextPackage:b\nDailyInstance|1:I" +
    "d:u,2:Star:u,3:Build:>UseBuild,2047:NextPackage:b\nTravelerDuelBossLevel|1:Id:u,2:Star:u,3:BuildId:u,4:Difficulty:u,2047:NextPackage:b\nTravelerDuelChallengeInfo|1:Unlock:u,2:Id:u,3:OpenTime:l,4:CloseTime:l,2047:NextPackage:b\nActivity|1:Id:u,2:StartTime:l,3:EndTime:l,2047:NextPackage:b\nActivityQuest|1:Id:u,2:Status:u,3:ActivityId:u,15:Progress:r>QuestProgress,2047:NextPackage:b\nActivityPeriodic|1:Ac" +
    "tivityId:u,2:FinalStatus:u,15:Quests:r>ActivityQuest,2047:NextPackage:b\nActivityLogin|1:ActivityId:u,2:Receive:u,3:Actual:u,2047:NextPackage:b\nActivityMining|1:ActivityId:u,2:Layer:u,3:Score:u,11:Quests:r>ActivityQuest,2047:NextPackage:b\nActivityCookieLevel|1:ActivityId:u,2:LevelId:u,3:MaxScore:u,4:FirstComplete:u,2047:NextPackage:b\nActivityCookie|1:ActivityId:u,11:Quests:r>ActivityQuest,12:Levels" +
    ":r>ActivityCookieLevel,2047:NextPackage:b\nActivityTowerDefenseLevel|1:Id:u,2:Star:u,2047:NextPackage:b\nActivityTowerDefense|1:ActivityId:u,2:Stories:ru,3:Levels:r>ActivityTowerDefenseLevel,11:Quests:r>ActivityQuest,2047:NextPackage:b\nActivityTrial|1:CompletedGroupIds:ru,2047:NextPackage:b\nActivityCG|1:Read:u,2047:NextPackage:b\nActivityLevel|1:Id:u,2:Star:u,3:Build:>UseBuild,2047:NextPackage:b\nActi" +
    "vityLevels|1:levels:r>ActivityLevel,2047:NextPackage:b\nActivityAvg|1:RewardIds:ru,2047:NextPackage:b\nMilkout|1:Levels:r>MilkoutLevel,2:Characters:r>MilkoutCharacter,2047:NextPackage:b\nMilkoutLevel|1:Id:u,2:FirstComplete:u,2047:NextPackage:b\nMilkoutCharacter|1:Id:u,2:BattleTimes:u,2047:NextPackage:b\nActivityPenguinCardLevel|1:Id:u,2:Star:u,3:Score:u,4:Difficulty:u,5:Data:s,2047:NextPackage:b\nActivi" +
    "tyPenguinCard|1:ActivityId:u,2:Levels:r>ActivityPenguinCardLevel,3:Quests:r>ActivityQuest,2047:NextPackage:b\nActivityDouble|1:ActivityId:u,2:DailyUseTimes:u,3:Quests:r>ActivityQuest,2047:NextPackage:b\nAffinityInfo|1:CharId:u,2:AffinityLevel:u,3:AffinityExp:u,4:Rewards:r>ItemTpl,2047:NextPackage:b\nActivityState|1:Id:u,2:RedDot:u,3:Banner:u,2047:NextPackage:b\nChat|1:Id:u,2:Options:ru,3:Process:u,204" +
    "7:NextPackage:b\nContacts|1:CharId:u,2:TriggerTime:l,3:Chats:r>Chat,14:OptTime:l,15:Top:u,2047:NextPackage:b\nInfinityTowerLevelInfo|1:Id:u,2:LevelId:u,3:ChallengeIds:ru,2047:NextPackage:b\nCollectResp|1:Status:u,2:Items:>ChangeInfo,2047:NextPackage:b\nEquipmentAttr|1:Id:u,2:Value:i,2047:NextPackage:b\nEquipmentInfo|1:Id:u,2:Tid:u,3:Exp:u,4:Lock:u,5:Tags:ru,6:Attrs:r>EquipmentAttr,2047:NextPackage:b\nEq" +
    "uipmentInstance|1:Id:u,2:Star:u,15:BuildId:u,2047:NextPackage:b\nAgentInfo|1:Id:u,2:ProcessTime:u,3:CharIds:ru,4:BuildId:u,5:StartTime:l,2047:NextPackage:b\nAgentData|1:Infos:r>AgentInfo,2:NewAgentIds:ru,3:DailyIds:ru,4:WeeklyIds:ru,2047:NextPackage:b\nHonorInfo|1:Id:u,2:AffinityLV:u,2047:NextPackage:b\nCardInfo|1:Id:u,2:New:u,2047:NextPackage:b\nVampireSurvivorEvent|1:EventType:u,2:Numbers:ru,2047:Nex" +
    "tPackage:b\nVampireSurvivorLevelReward|1:Level:u,2:Pkg:>VampireSurvivorFateCardSelect,2047:NextPackage:b\nVampireSurvivorFateCardSelect|1:Cards:r>CardInfo,2:ReRoll:u,2047:NextPackage:b\nScoreBossLevel|1:LevelId:u,2:BuildId:u,3:Score:u,4:Star:u,5:SkillScore:u,6:CharIds:ru,2047:NextPackage:b\nVampireSurvivorLevel|1:Id:u,2:Score:u,3:BuildIds:ru,4:Passed:u,2047:NextPackage:b\nVampireSurvivorRecordInfo|1:Re" +
    "cords:r>VampireSurvivorLevel,2:Season:>VampireSurvivorLevel,3:SeasonScore:u,2047:NextPackage:b\nSkillInstance|1:Id:u,2:Star:u,3:First:u,4:ThreeStar:u,5:Build:>UseBuild,2047:NextPackage:b\nWeekBossLevel|1:Id:u,2:Time:u,3:Build:>UseBuild,4:First:u,2047:NextPackage:b\nScoreBossState|1:New:u,2047:NextPackage:b\nNPCAffinity|1:NPCId:u,2:Affinity:u,3:PlotIds:ru,2047:NextPackage:b\nCharGemInstance|1:Id:u,2:Sta" +
    "r:u,3:First:u,4:ThreeStar:u,5:Build:>UseBuild,6:RewardType:u,2047:NextPackage:b\nCharGemPreset|1:Name:s,2:SlotGem:ri,2047:NextPackage:b\nCharGemPresets|1:InUsePresetIndex:u,2:CharGemPresets:r>CharGemPreset,2047:NextPackage:b\nCharGem|1:Lock:u,2:Attributes:ru,3:AlterAttributes:ru,4:OverlockCount:ru,5:AlterOverlockCount:ru,2047:NextPackage:b\nCharGemSlot|1:Id:u,2:AlterGems:r>CharGem,2047:NextPackage:b\nA" +
    "ctivityTask|1:ActivityTasks:>Quests,2:GroupIds:ru,2047:NextPackage:b\nActivityShop|1:Shops:r>ResidentShop,2047:NextPackage:b\nTutorialLevel|1:LevelId:u,2:Passed:u,3:RewardReceived:u,2047:NextPackage:b\nBuildConvertContent|1:Id:u,2:Num:u,2047:NextPackage:b\nActivityBuildConvert|1:Contents:r>BuildConvertContent,2:Quests:r>ActivityQuest,2047:NextPackage:b\nVampireClientData|1:Efts:r>FateCardEftCnt,2:Limit" +
    "s:r>FateCardTimeLimit,3:FateCardTimer:u,4:Level:u,5:Exp:u,2047:NextPackage:b\nFateCardEftCnt|1:Id:u,2:EftId:u,3:Count:u,2047:NextPackage:b\nFateCardTimeLimit|1:Id:u,2:TimeLimit:u,2047:NextPackage:b\nTrekkerVersusShow|1:Difficult:u,2:IdleTime:l,3:IdleValues:r>IdleValue,4:SelfHotValue:u,5:RivalHotValue:u,2047:NextPackage:b\nIdleValue|1:TypeId:u,2:Value:u\nActivityTrekkerVersus|1:DayNum:u,2:Level:u,3:Exp:" +
    "u,4:Build:>UseBuild,5:Show:>TrekkerVersusShow,6:HotValueRewardIds:ru,7:DuelRewardIds:ru,8:Quests:r>ActivityQuest,9:Results:r>HistoryResult,2047:NextPackage:b\nHistoryResult|1:SelfHotValue:u,2:RivalHotValue:u,3:TargetId:u\nActivityStoryChoice|1:Group:u,2:Value:u,2047:NextPackage:b\nActivityStory|1:Id:u,2:Major:r>ActivityStoryChoice,3:Personality:r>ActivityStoryChoice,2047:NextPackage:b\nActivityStoryCh" +
    "apter|1:Evidences:ru,2:Build:>UseBuild,3:Stories:r>ActivityStory,2047:NextPackage:b\nLastRead|1:Type:u,2:Story:>LastReadStory,3:StorySet:>LastReadStorySet,4:ActivityStory:>LastReadActivityStory,2047:NextPackage:b\nLastReadStory|1:Idx:u,2047:NextPackage:b\nLastReadStorySet|1:ChapterId:u,2:SectionId:u,2047:NextPackage:b\nLastReadActivityStory|1:ChapterId:u,2:StoryId:u,2047:NextPackage:b\nActivityThrowGif" +
    "tLevel|1:LevelId:u,2:MaxScore:u,3:FirstComplete:u,2047:NextPackage:b\nActivityThrowGiftItem|1:ItemId:u,2:Count:u,2047:NextPackage:b\nActivityThrowGift|1:Levels:r>ActivityThrowGiftLevel,2:Items:r>ActivityThrowGiftItem,2047:NextPackage:b\nActivityGDSLevel|1:LevelId:u,2:MaxScore:u,3:FirstComplete:u,2047:NextPackage:b\nActivityGDS|1:Levels:r>ActivityGDSLevel,2047:NextPackage:b\nActivityHonor|1:Id:u,2:Lv:u," +
    "2047:NextPackage:b\nActivityPersonalityModel|1:ChapterId:u,2:A:u,3:B:u,4:C:u,2047:NextPackage:b\nActivityHistoryStory|1:Id:u,2:Major:r>ActivityStoryChoice,3:Personality:r>ActivityStoryChoice,4:Receive:u,2047:NextPackage:b\nActivityHistoryStoryChapter|1:ChapterId:u,2:Build:>UseBuild,3:Evidences:ru,4:Stories:r>ActivityHistoryStory,2047:NextPackage:b\nActivityShare|1:State:b,2047:NextPackage:b\nTraceHuntB" +
    "ossCollection|1:Id:u,2:HuntCount:u,3:AssistHuntCount:u,2047:NextPackage:b\nTraceHuntLogEntry|1:Tid:u,2:args:rs,2047:NextPackage:b\nTraceHuntItemInfo|1:Tid:u,2:EnergyOverflow:u,3:ConvertedCount:u,4:GrantedCount:u,5:DailyCount:u,2047:NextPackage:b\nTraceHuntItem|1:Tid:u,2:PointQty:i,3:ConvertQty:i,4:GrantQty:i,5:DailyCount:u,2047:NextPackage:b\nTraceHuntState|1:BossRewardCanReceive:u,2047:NextPackage:b\n" +
    "ActivityIceCreamLevel|1:LevelId:u,2:Score:u,3:FirstComplete:u,2047:NextPackage:b\nActivityIceCream|1:ActivityId:u,2:Levels:r>ActivityIceCreamLevel,3:Quests:r>ActivityQuest,2047:NextPackage:b\nActivityIceCreamLevelSettleSucceed|1:Change:>ChangeInfo,2:Passed:u,2047:NextPackage:b\nActivitySoldier|1:CurGradeChallengeId:u,2:Score:u,3:GradeChallengeId:u,4:Stage:u,5:NodeIndex:u,6:Quests:r>ActivityQuest,2047" +
    ":NextPackage:b\nActivityMathParkourLevel|1:LevelId:u,2:Score:u,3:Star:u,2047:NextPackage:b\nActivityMathParkour|1:ActivityId:u,2:Levels:r>ActivityMathParkourLevel,3:Quests:r>ActivityQuest,2047:NextPackage:b\nActivityMathParkourLevelSettleSucceed|1:Change:>ChangeInfo,2:Passed:u,2047:NextPackage:b\nUseBuild|1:Type:u,2:BuildId:u,2047:NextPackage:b\nGuideMissionState|1:New:u,2047:NextPackage:b\nActivityMail" +
    "Bind|1:Bind:u,2047:NextPackage:b\nActivityMallLogin|1:ActivityId:u,2:active:u,3:Received:u,4:LoginDays:u,2047:NextPackage:b\nTowerVitaOption|1:Id:u,2:Boolean:u,3:Integer:u,4:List:>UI32s,2047:NextPackage:b\nTowerVitaProject|1:Id:u,2:Name:s,3:Options:r>TowerVitaOption,2047:NextPackage:b\nSoldierBattleReportChess|1:Id:u,2:Star:u,2047:NextPackage:b\nSoldierBattleReport|1:ReportId:s,2:GradeChallengeId:u,3:B" +
    "ossAbilityId:u,4:NodeIndex:u,5:RemainingHP:u,6:TotalCoin:u,7:CardIds:ru,8:Chess:r>SoldierBattleReportChess,9:Result:u,10:Score:u,11:Version:s,12:Time:u,2047:NextPackage:b\nDormOutInfo|1:DormName:s,2:CollectionValue:u,2047:NextPackage:b\nAchievementRewardReq|1:Ids:ru,2047:NextPackage:b\nActivityArchiveStoryApplyReq|1:ActivityId:u,2:StoryId:u,3:Build:>UseBuild,2047:NextPackage:b\nActivityStorySettleReq|" +
    "1:ActivityId:u,2:List:r>ActivityStorySettle,14:Events:>Events,15:Evidences:ru,2047:NextPackage:b\nActivityStorySettle|1:StoryId:u,2:Major:r>ActivityStoryOptions,3:Personality:r>ActivityStoryOptions,2047:NextPackage:b\nActivityStoryOptions|1:Group:u,2:Choice:u,3:Factor:u,2047:NextPackage:b\nActivityArchiveStoryChapterPassReq|1:ChapterId:u,2047:NextPackage:b\nActivityArchiveStorySettleReq|1:ActivityId:u" +
    ",2:List:r>ActivityStorySettle,14:Events:>Events,15:Evidences:ru,2047:NextPackage:b\nActivityAvgRewardReceiveReq|1:ActivityId:u,2:LevelId:u,8:Events:>Events,2047:NextPackage:b\nActivityCookieQuestRewardReceiveReq|1:ActivityId:u,2:QuestId:u,2047:NextPackage:b\nActivityCookieSettleReq|1:ActivityId:u,2:LevelId:u,3:Score:u,4:CookieNum:u,5:PackageNum:u,6:PerfectNum:u,7:ExcellentNum:u,8:MissNum:u,9:Good:u,2" +
    "047:NextPackage:b\nActivityJointDrill|1:Meta:>JointDrillMeta,2:PassedLevels:r>JointDrillLevel,3:Quests:r>ActivityQuest,9:Mode1:>Mode1Meta,10:Mode2:>Mode2Meta,2047:NextPackage:b\nJointDrillMeta|1:LevelId:u,2:Floor:u,3:StartTime:l,5:Teams:r>JointDrillTeam,6:Simulate:u,7:TotalScore:u,2047:NextPackage:b\nMode1Meta|1:BossHp:u,2:BossHpMax:u,3:Record:b,2047:NextPackage:b\nMode2Meta|1:BossHps:r>JointDrillBoss" +
    "Hp,2:BossHpMaxes:r>JointDrillBossHp,3:Record:b,2047:NextPackage:b\nJointDrillBossHp|1:Id:u,2:Hp:u,2047:NextPackage:b\nJointDrillTeam|1:Chars:r>JointDrillChar,2:BuildScore:u,3:Damage:u,4:Time:u,5:BuildId:u,2047:NextPackage:b\nJointDrillChar|1:CharId:u,2:CharLevel:u,2047:NextPackage:b\nJointDrillLevel|1:LevelId:u,2:Score:u,2047:NextPackage:b\nJointDrillSettle|1:Change:>ChangeInfo,2:Items:r>ItemTpl,3:Figh" +
    "tScore:u,4:HpScore:u,5:DifficultyScore:u,13:Old:u,14:New:u,15:Token:s,2047:NextPackage:b\nActivityMsg|1:Id:u,2:Periodic:>ActivityPeriodic,3:Login:>ActivityLogin,4:Mining:>ActivityMining,5:JointDrill:>ActivityJointDrill,6:Cookie:>ActivityCookie,7:TowerDefense:>ActivityTowerDefense,8:Trial:>ActivityTrial,9:CG:>ActivityCG,10:Levels:>ActivityLevels,11:Avg:>ActivityAvg,12:Task:>ActivityTask,13:Shop:>Act" +
    "ivityShop,14:BdConvert:>ActivityBuildConvert,15:TrekkerVersus:>ActivityTrekkerVersus,16:StoryChapter:>ActivityStoryChapter,17:Milkout:>Milkout,18:PenguinCard:>ActivityPenguinCard,19:ThrowGift:>ActivityThrowGift,20:GDS:>ActivityGDS,21:Double:>ActivityDouble,22:HistoryStoryChapter:>ActivityHistoryStoryChapter,23:Share:>ActivityShare,24:IceCream:>ActivityIceCream,25:Soldier:>ActivitySoldier,26:MathPa" +
    "rkour:>ActivityMathParkour,27:MailBind:>ActivityMailBind,28:MallLogin:>ActivityMallLogin,2047:NextPackage:b\nActivityResp|1:List:r>ActivityMsg,2047:NextPackage:b\nActivityDoubleQuestRewardReq|1:ActivityId:u,2:QuestId:u,2047:NextPackage:b\nActivityGDSSettleReq|1:ActivityId:u,2:LevelId:u,3:Floor:u,4:Score:u,5:CompletedTaskCount:u,6:Items:r>ActivityGDSItem,7:Skills:r>ActivityGDSSkill,2047:NextPackage:b\n" +
    "ActivityGDSItem|1:ItemId:u,2:PickCount:u,2047:NextPackage:b\nActivityGDSSkill|1:SkillId:u,2:UseCount:u,2047:NextPackage:b\nActivityHistoryStoryApplyReq|1:ActivityId:u,2:StoryId:u,3:Build:>UseBuild,2047:NextPackage:b\nActivityHistoryStorySettleReq|1:ActivityId:u,2:List:r>ActivityStorySettle,14:Events:>Events,15:Evidences:ru,2047:NextPackage:b\nActivityIceCreamLevelSettleReq|1:ActivityId:u,2:LevelId:u,3" +
    ":LevelType:u,4:OrderCount:u,5:TotalScore:u,6:StreakCount:u,7:PropCount:u,2047:NextPackage:b\nActivityLevelsApplyReq|1:ActivityId:u,2:LevelId:u,3:Build:>UseBuild,2047:NextPackage:b\nActivityLevelsSettleReq|1:ActivityId:u,2:Star:u,3:Events:>Events,2047:NextPackage:b\nActivityLevelsSettleResp|1:ChangeInfo:>ChangeInfo,2:First:r>ItemTpl,3:Exp:u,4:Fixed:r>ItemTpl,2047:NextPackage:b\nActivityLevelsSweepReq|1" +
    ":ActivityId:u,2:LevelId:u,3:Times:u,15:Events:>Events,2047:NextPackage:b\nActivityLevelsSweepReward|1:AwardItems:r>ItemTpl,2:Exp:u,2047:NextPackage:b\nActivityLevelsSweepResp|1:ChangeInfo:>ChangeInfo,2:Rewards:r>ActivityLevelsSweepReward,2047:NextPackage:b\nActivityMathParkourLevelSettleReq|1:ActivityId:u,2:LevelId:u,3:TotalScore:u,4:State:u,5:PropCount:u,2047:NextPackage:b\nMiningTreasure|1:Id:u,2:Po" +
    "sIndex:ru,3:Received:u,2047:NextPackage:b\nMiningGrid|1:Id:u,2:PosIndex:u,3:GridType:u,4:Marked:u,2047:NextPackage:b\nMiningSupport|1:Id:u,2:UsableCount:i,3:UsedCount:i,2047:NextPackage:b\nMiningMap|1:Id:u,2:Treasures:r>MiningTreasure,3:Grids:r>MiningGrid,2047:NextPackage:b\nMiningLayer|1:Layer:u,3:Map:>MiningMap,4:Supports:r>MiningSupport,2047:NextPackage:b\nMiningProcess|1:EffectType:i,2:EffectedGrid" +
    "s:r>MiningGrid,2047:NextPackage:b\nMiningChangeInfo|1:Score:u,2:Processes:r>MiningProcess,3:ReceivedTreasures:ru,2047:NextPackage:b\nActivityMiningApplyReq|1:ActivityId:u,2047:NextPackage:b\nActivityMiningApplyResp|1:Layer:>MiningLayer,2:MiningChangeInfo:>MiningChangeInfo,2047:NextPackage:b\nActivityMiningDigReq|1:ActivityId:u,2:GridId:u,2047:NextPackage:b\nActivityMiningDigResp|1:ChangeInfo:>ChangeInf" +
    "o,2:MiningChangeInfo:>MiningChangeInfo,2047:NextPackage:b\nActivityMiningMoveToNextLayerReq|1:ActivityId:u,2047:NextPackage:b\nActivityMiningMoveToNextLayerResp|1:Layer:>MiningLayer,2:MiningChangeInfo:>MiningChangeInfo,2047:NextPackage:b\nActivityMiningQuestRewardReceiveReq|1:ActivityId:u,2:QuestId:u,3:GroupId:u,2047:NextPackage:b\nActivityMiningQuestRewardReceiveResp|1:QuestRewards:r>ItemTpl,2:Change" +
    "Info:>ChangeInfo,2047:NextPackage:b\nActivityMiningStoryRewardReceiveReq|1:ActivityId:u,2:StoryId:u,2047:NextPackage:b\nActivityPenguinCardEndlessLevelSaveReq|1:LevelId:u,2:Data:s,3:Score:u,2047:NextPackage:b\nActivityPenguinCardSettleReq|1:LevelId:u,2:Star:u,3:Score:u,4:Difficulty:u,2047:NextPackage:b\nActivityPenguinCardQuestReceiveReq|1:ActivityId:u,2:QuestId:u,3:GroupId:u,2047:NextPackage:b\nActivi" +
    "tyPeriodicRewardReq|1:ActivityId:u,2:QuestId:u,2047:NextPackage:b\nActivityReturneeInfoResp|1:Reunion:>ActivityReturneeReunionInfo,2:Login:>ActivityReturneeLoginInfo,3:Avg:>ActivityReturneeAvgInfo,4:Quests:>Quests,5:QuestPoint:>ActivityReturneeQuestPointInfo,6:MallInfo:>ActivityReturneeMallInfo,2047:NextPackage:b\nActivityReturneeReunionInfo|1:ReunionReward:u,2047:NextPackage:b\nActivityReturneeLogin" +
    "Info|1:Receive:u,2:Actual:u,2047:NextPackage:b\nActivityReturneeAvgInfo|1:Avg:u,2047:NextPackage:b\nActivityReturneeQuestPointInfo|1:Point:u,2:Received:b,2047:NextPackage:b\nActivityReturneeMallInfo|1:Ids:rs,2:Card:>ActivityReturneeCard,2047:NextPackage:b\nActivityReturneeCard|1:Id:s,2:Remaining:u,3:Received:u,2047:NextPackage:b\nActivityShareRewardReq|1:ActivityId:u,2:ChannelId:u,2047:NextPackage:b\nAc" +
    "tivityShopPurchaseReq|1:ActivityId:u,2:ShopId:u,3:RefreshTime:l,4:GoodsId:u,5:Number:u,2047:NextPackage:b\nActivityShopPurchaseResp|1:IsRefresh:u,2:Shop:>ResidentShop,3:PurchasedNumber:u,4:Change:>ChangeInfo,2047:NextPackage:b\nActivitySoldierQuestRewardReceiveReq|1:ActivityId:u,2:GroupId:u,3:QuestId:u,2047:NextPackage:b\nActivityStoryApplyReq|1:ActivityId:u,2:StoryId:u,3:Build:>UseBuild,2047:NextPac" +
    "kage:b\nActivityTaskRewardReceiveReq|1:GroupId:u,2:TabType:u,3:QuestId:u,2047:NextPackage:b\nActivityThrowGiftSettleReq|1:ActivityId:u,2:LevelId:u,3:ThrowGiftCount:u,4:HitGiftCount:u,5:Score:u,6:UseItems:r>ActivityThrowGiftUsedItem,7:Win:u,2047:NextPackage:b\nActivityThrowGiftUsedItem|1:ItemId:u,2:Count:u,2047:NextPackage:b\nActivityTowerDefenseLevelApplyReq|1:Level:u,2:Characters:ru,3:ItemId:u,2047:N" +
    "extPackage:b\nActivityTowerDefenseLevelSettleReq|1:LevelId:u,2:Star:u,2047:NextPackage:b\nActivityTowerDefenseQuestReceiveReq|1:ActivityId:u,2:QuestId:u,3:GroupId:u,2047:NextPackage:b\nActivityTrekkerVersusApplyReq|1:ActivityId:u,2:LevelId:u,3:Build:>UseBuild,4:AffixIds:ru,2047:NextPackage:b\nActivityTrekkerVersusIdleRewardReceiveResp|1:Change:>ChangeInfo,2:AwardItems:r>ItemTpl,3:IdleTime:l,2047:NextP" +
    "ackage:b\nActivityTrekkerVersusRankBoostReq|1:ActivityId:u,2:Items:r>ItemInfo,2047:NextPackage:b\nActivityTrekkerVersusRankBoostResp|1:Level:u,2:Exp:u,3:SelfHotValue:u,4:RivalHotValue:u,5:Change:>ChangeInfo,6:AwardItems:r>ItemTpl,2047:NextPackage:b\nActivityTrekkerVersusRewardReceiveResp|1:Change:>ChangeInfo,2:AwardItems:r>ItemTpl,2047:NextPackage:b\nActivityTrekkerVersusScheduleRewardReceiveReq|1:Act" +
    "ivityId:u,2:ScheduleType:u,2047:NextPackage:b\nActivityTrekkerVersusScheduleRewardReceiveResp|1:ScheduleType:u,2:RewardIds:ru,3:Change:>ChangeInfo,4:AwardItems:r>ItemTpl,2047:NextPackage:b\nActivityTrekkerVersusSettleReq|1:ActivityId:u,2:Time:u,3:Passed:u,8:Events:>Events,2047:NextPackage:b\nActivityTrekkerVersusSettleResp|1:Show:>TrekkerVersusShow,2047:NextPackage:b\nActivityTrialRewardReceiveReq|1:A" +
    "ctivityId:u,2:GroupId:u,2047:NextPackage:b\nAgentApplyReq|1:Apply:r>AgentApplyInfo,2047:NextPackage:b\nAgentApplyInfo|1:Id:u,2:ProcessTime:u,3:CharIds:ru,4:BuildId:u,2047:NextPackage:b\nAgentApplyResp|1:Infos:r>AgentRespInfo,2047:NextPackage:b\nAgentRespInfo|1:Id:u,2:BeginTime:l,2047:NextPackage:b\nAgentGiveUpReq|1:Id:u,2047:NextPackage:b\nAgentGiveUpResp|1:CharIds:ru,2:BuildId:u,2047:NextPackage:b\nAgen" +
    "tRewardReceiveReq|1:Id:u,2047:NextPackage:b\nAgentRewardReceiveResp|1:CharIds:ru,2:BuildIds:ru,3:RewardShows:r>AgentRewardShow,4:Change:>ChangeInfo,2047:NextPackage:b\nAgentRewardShow|1:Id:u,2:Rewards:r>ItemTpl,3:Bonus:r>ItemTpl,4:SpecialRewards:r>ItemTpl,2047:NextPackage:b\nBattlePassInfo|1:Id:u,2:Mode:u,3:Version:u,4:Deadline:l,5:Level:u,6:Exp:u,7:ExpThisWeek:u,8:BasicReward:b,9:PremiumReward:b,10:" +
    "DailyQuests:>Quests,11:WeeklyQuests:>Quests,2047:NextPackage:b\nBattlePassLevelBuyResp|1:Change:>ChangeInfo,2:Level:u,2047:NextPackage:b\nBattlePassOrderReq|1:Mode:u,2:Version:u,2047:NextPackage:b\nBattlePassOrderCollectResp|1:CollectResp:>CollectResp,2:Mode:u,3:Level:u,4:Version:u,2047:NextPackage:b\nBattlePassQuestRewardResp|1:Level:u,2:Exp:u,3:ExpThisWeek:u,2047:NextPackage:b\nBattlePassRewardReceiv" +
    "eReq|1:All:>Nil,2:Basic:u,3:Premium:u,4:Version:u,2047:NextPackage:b\nBattlePassRewardReceiveResp|1:BasicReward:b,2:PremiumReward:b,3:Change:>ChangeInfo,2047:NextPackage:b\nTravelerDuelBattleSamples|1:Sample:r>TravelerDuelBattleSample,2:Checksum:u,2047:NextPackage:b\nTravelerDuelBattleData|1:Meta:>TravelerDuelMetaInfo,2:Samples:>TravelerDuelBattleSamples,3:Extra:b,2047:NextPackage:b\nTravelerDuelMetaI" +
    "nfo|1:Id:u,2:Version:u,3:Zone:s,4:MissionId:u,5:Season:u,6:PlayerId:u,7:Nickname:s,8:Duration:u,9:Rank:u,10:Time:l,11:Score:u,2047:NextPackage:b\nTravelerDuelBattleSample|1:FromSrcAtk:i,2:FromPerkIntensityRatio:f,3:FromSlotDmgRatio:f,4:FromEE:f,5:FromGenDmgRatio:f,6:FromDmgPlus:i,7:FromCritRatio:f,8:FromFinalDmgRatio:f,9:FromFinalDmgPlus:i,10:ToErAmend:f,11:ToDefAmend:f,12:ToRcdSlotDmgRatio:f,13:To" +
    "EERCD:f,14:ToGenDmgRcdRatio:f,15:ToDmgPlusRcd:f,16:Dmg:l,17:CritRate:f,18:Hp:l,2047:NextPackage:b\nRankChange|1:Old:u,2:New:u,3:Token:s,2047:NextPackage:b\nStarTowerInfo|1:Meta:>StarTowerMeta,2:Room:>StarTowerRoom,3:Bag:>StarTowerBag,2047:NextPackage:b\nStarTowerMeta|1:Id:u,2:CharHp:u,3:TeamLevel:u,4:TeamExp:u,5:Chars:r>StarTowerChar,6:Discs:r>StarTowerDisc,7:DateLen:u,8:ClientData:s,9:ActiveSecondar" +
    "yIds:ru,10:NPCInteractions:u,11:TowerGrowthNodes:ru,12:ResurrectionCnt:u,14:TotalTime:u,15:TotalDamages:ru,16:BuildId:u,17:DataVersion:u,2047:NextPackage:b\nStarTowerDisc|1:Id:u,2:Level:u,3:Phase:u,4:Star:u,2047:NextPackage:b\nStarTowerChar|1:Id:u,2:Gems:r>StarTowerCharGem,3:Level:u,4:SkillLvs:ru,5:AffinityLevel:u,6:Advance:u,7:TalentNodes:b,2047:NextPackage:b\nStarTowerCharGem|1:Attributes:ru,2:Slot" +
    "Id:u,3:OverlockCount:ru,2047:NextPackage:b\nStarTowerBag|1:FateCard:r>FateCardInfo,2:Potentials:r>PotentialInfo,3:Items:r>TowerItemInfo,4:Res:r>TowerResInfo,2047:NextPackage:b\nStarTowerRoom|1:Data:>StarTowerRoomData,2:Cases:r>StarTowerRoomCase,2047:NextPackage:b\nStarTowerRoomData|1:Floor:u,2:MapId:u,3:ParamId:u,4:RoomType:u,5:MapParam:s,6:MapTableId:u,2047:NextPackage:b\nStarTowerRoomCase|1:Id:u,2:B" +
    "attleCase:>BattleCaseData,3:DoorCase:>DoorCaseData,4:SelectSpecialPotentialCase:>SelectSpecialPotentialCaseData,5:SelectPotentialCase:>SelectPotentialCaseData,6:SelectFateCardCase:>SelectFateCardCaseData,8:SelectOptionsEventCase:>SelectOptionsEventCaseData,9:RecoveryHPCase:>RecoveryHPCaseData,10:NpcRecoveryHPCase:>NpcRecoveryHPCaseData,11:HawkerCase:>HawkerCaseData,12:StrengthenMachineCase:>Streng" +
    "thenMachineCaseData,15:SyncHPCase:>SyncHPCaseData,2047:NextPackage:b\nBattleCaseData|1:TimeLimit:u,2:FateCard:u,3:SubNoteSkillNum:u,2047:NextPackage:b\nDoorCaseData|1:Floor:u,2:Type:u,2047:NextPackage:b\nSelectSpecialPotentialCaseData|1:Ids:ru,2:TeamLevel:u,3:NewIds:ru,7:CanReRoll:u,8:ReRollPrice:u,2047:NextPackage:b\nSelectPotentialCaseData|1:Infos:r>PotentialInfo,2:TeamLevel:u,3:NewIds:ru,12:LuckyId" +
    "s:ru,13:CanReRoll:u,14:ReRollPrice:u,15:Type:u,2047:NextPackage:b\nSelectOptionsEventCaseData|1:EvtId:u,2:Options:ru,3:FailedIdxes:ru,4:NPCId:u,5:Done:u,6:Infos:r>NPCAffinityInfo,2047:NextPackage:b\nSelectFateCardCaseData|1:Ids:ru,2:NewIds:ru,3:Give:u,7:CanReRoll:u,8:ReRollPrice:u,2047:NextPackage:b\nRecoveryHPCaseData|1:EffectId:u,2047:NextPackage:b\nNpcRecoveryHPCaseData|1:EffectId:u,2047:NextPackag" +
    "e:b\nSyncHPCaseData|2047:NextPackage:b\nHawkerGoods|1:Sid:u,2:Idx:u,3:CharPos:u,4:Price:i,5:Discount:i,6:Type:u,7:GoodsId:u,15:Tag:u,2047:NextPackage:b\nHawkerCaseData|1:List:r>HawkerGoods,2:Purchase:ru,7:CanReRoll:u,8:ReRollPrice:u,9:ReRollTimes:u,2047:NextPackage:b\nInteractHawkerReq|1:Sid:u,2:ReRoll:u,3:Auto:u,2047:NextPackage:b\nInteractStrengthenMachineResp|1:BuySucceed:u,2047:NextPackage:b\nStreng" +
    "thenMachineCaseData|1:Times:u,7:FirstFree:u,8:Discount:u,2047:NextPackage:b\nInteractEnterReq|1:MapId:u,2:ParamId:u,3:DateLen:u,4:ClientData:s,5:MapParam:s,6:MapTableId:u,7:DataVersion:u,2047:NextPackage:b\nInteractEnterResp|1:Room:>StarTowerRoom,2047:NextPackage:b\nInteractBattleEndReq|1:Victory:>VictoryData,2:Defeat:u,2047:NextPackage:b\nVictoryData|1:HP:u,2:Time:u,3:DateLen:u,4:ClientData:s,5:fateC" +
    "ardUsage:r>FateCardUsage,6:Damages:ru,7:DataVersion:u,15:Events:>Events\nInteractBattleEndResp|1:Victory:>VictoryData,2:Defeat:>DefeatData,2047:NextPackage:b\nDefeatData|1:FinalScore:u,2:SeasonId:u\nInteractRecoveryHPReq|1:Hp:u,2047:NextPackage:b\nFateCardUsage|1:Id:u,2:Times:u,2047:NextPackage:b\nInteractSelectReq|1:Index:u,2:ReRoll:u,3:Auto:u,2047:NextPackage:b\nInteractSelectResp|1:Resp:>Success,2:Se" +
    "lectSpecialPotentialCase:>SelectSpecialPotentialCaseData,3:SelectPotentialCase:>SelectPotentialCaseData,4:SelectFateCardCase:>SelectFateCardCaseData,5:HawkerCase:>HawkerCaseData,2047:NextPackage:b\nSuccess|1:Items:r>ItemTpl,2:OptionsResult:u,3:FateCard:r>FateCardInfo,4:SubNoteSkills:r>SubNoteSkillInfo,5:OptionsParamId:u,6:AffinityChange:r>NPCAffinityChange\nFateCardInfo|1:Tid:u,2:Qty:i,3:Remain:i,4:" +
    "Room:i,2047:NextPackage:b\nPotentialInfo|1:Tid:u,2:Level:i,2047:NextPackage:b\nTowerItemInfo|1:Tid:u,2:Qty:i,2047:NextPackage:b\nTowerResInfo|1:Tid:u,2:Qty:i,2047:NextPackage:b\nSubNoteSkillInfo|1:Tid:u,2:Qty:i,3:New:u,4:LuckyLevel:u,2047:NextPackage:b\nFirstAward|1:TowerId:u,2:Items:r>ItemTpl,2047:NextPackage:b\nSettleDataResp|1:Change:>ChangeInfo,2:Build:>StarTowerBuildInfo,3:Awards:r>FirstAward,4:Rew" +
    "ard:r>NPCAffinityLevelReward,5:NpcInteraction:u,6:TowerRewards:r>ItemTpl,14:TotalTime:u,15:TotalDamages:ru,2047:NextPackage:b\nTowerBuildChar|1:CharId:u,2:PotentialCnt:u,2047:NextPackage:b\nBuildPotential|1:PotentialId:u,2:Level:u,2047:NextPackage:b\nStarTowerBuildInfo|1:Brief:>StarTowerBuildBrief,2:Detail:>StarTowerBuildDetail,3:BuildCoin:u,2047:NextPackage:b\nStarTowerBuildBrief|1:Id:u,2:Name:s,3:Lo" +
    "ck:u,4:Preference:u,5:Score:u,6:DiscIds:ru,7:Chars:r>TowerBuildChar,8:StarTowerId:u,2047:NextPackage:b\nStarTowerBuildDetail|1:Potentials:r>BuildPotential,2:SubNoteSkills:r>ItemTpl,3:ActiveSecondaryIds:ru,4:ModifierState:u,2047:NextPackage:b\nStarTowerBookCharPotentialBrief|1:CharId:u,2:Count:u,2047:NextPackage:b\nStarTowerBookPotential|1:Id:u,2:Level:u,2047:NextPackage:b\nStarTowerBookCharPotential|1" +
    ":CharId:u,2:Potentials:r>StarTowerBookPotential,2047:NextPackage:b\nTowerChangeData|1:Infos:r>SubNoteSkillInfo,2:Secondaries:r>ActiveSecondaryChange,2047:NextPackage:b\nActiveSecondaryChange|1:SecondaryId:u,2:Active:u,2047:NextPackage:b\nNPCAffinityInfo|1:NPCId:u,2:Affinity:u,2047:NextPackage:b\nNPCAffinityChange|1:NPCId:u,2:Affinity:u,3:Increase:u,2047:NextPackage:b\nNPCAffinityLevelReward|1:Change:>N" +
    "PCAffinityChange,2:Items:r>ItemTpl,2047:NextPackage:b\nPotentialPreselection|1:Id:u,2:Name:s,3:Preference:u,4:CharPotentials:r>StarTowerBookCharPotential,5:Timestamp:u,2047:NextPackage:b\nBuildConvertDetailListGetResp|1:Details:r>StarTowerBuildInfo,2047:NextPackage:b\nBuildConvertGroupRewardReceiveResp|1:Ids:ru,2:Change:>ChangeInfo,3:AwardItems:r>ItemTpl,2047:NextPackage:b\nBuildConvertSubmitReq|1:Act" +
    "ivityId:u,2:ContentId:u,3:BuildIds:ru,2047:NextPackage:b\nBuildConvertSubmitResp|1:Change:>ChangeInfo,2:AwardItems:r>ItemTpl,3:Number:u,2047:NextPackage:b\nCharAdvanceRewardReceiveReq|1:CharId:u,2:Advance:u,2047:NextPackage:b\nCharAdvanceRewardReceiveResp|1:Flag:b,2:Change:>ChangeInfo,2047:NextPackage:b\nCharAffinityGiftSendReq|1:CharId:u,2:Items:r>ItemTpl,2047:NextPackage:b\nCharAffinityGiftSendResp|1" +
    ":Info:>AffinityInfo,2:Change:>ChangeInfo,3:SendGiftCnt:u,2047:NextPackage:b\nCharAffinityQuestRewardReceiveReq|1:CharId:u,2:QuestId:u,2047:NextPackage:b\nCharAffinityQuestRewardReceiveResp|1:Info:>AffinityInfo,2:Change:>ChangeInfo,2047:NextPackage:b\nCharArchiveRewardReceiveReq|1:ArchiveId:u,2047:NextPackage:b\nCharDatingBranchASelectReq|1:OptionId:u,2047:NextPackage:b\nCharDatingBranchASelectResp|1:La" +
    "ndmarkEventIds:ru,2:BranchBOptionIds:ru,2047:NextPackage:b\nCharDatingBranchBSelectReq|1:OptionId:u,2047:NextPackage:b\nCharDatingBranchBSelectResp|1:CharacterEventId:u,2:AfterBranchId:u,7:Info:>AffinityInfo,8:Change:>ChangeInfo,2047:NextPackage:b\nCharDatingEventRewardReceiveReq|1:CharId:u,2:EventId:u,2047:NextPackage:b\nCharDatingGiftSendReq|1:CharId:u,2:Items:r>ItemTpl,2047:NextPackage:b\nCharDating" +
    "GiftSendResp|1:Info:>AffinityInfo,2:Change:>ChangeInfo,3:Show:r>ItemTpl,2047:NextPackage:b\nCharDatingLandmarkSelectReq|1:CharId:u,2:LandmarkId:u,2047:NextPackage:b\nCharDatingLandmarkSelectResp|1:BeforeBranchId:u,2:BranchAOptionIds:ru,7:Info:>AffinityInfo,8:Change:>ChangeInfo,2047:NextPackage:b\nCharGemEquipGemReq|1:CharId:u,2:SlotId:u,3:GemIndex:i,4:PresetId:u,2047:NextPackage:b\nCharGemGenerateReq|" +
    "1:CharId:u,2:SlotId:u,2047:NextPackage:b\nCharGemGenerateResp|1:CharGem:>CharGem,2:ChangeInfo:>ChangeInfo,2047:NextPackage:b\nCharGemInstanceApplyReq|1:Id:u,2:Build:>UseBuild,3:RewardType:u,2047:NextPackage:b\nCharGemInstanceSettleReq|1:Star:u,15:Events:>Events,2047:NextPackage:b\nCharGemInstanceSettleResp|1:First:u,2:ThreeStar:u,3:Change:>ChangeInfo,4:AwardItems:r>ItemTpl,5:FirstItems:r>ItemTpl,6:Thr" +
    "eeStarItems:r>ItemTpl,7:Exp:u,8:SurpriseItems:r>ItemTpl,9:DoubleItems:r>ItemTpl,2047:NextPackage:b\nCharGemInstanceSweepReq|1:Id:u,2:Times:u,3:RewardType:u,15:Events:>Events,2047:NextPackage:b\nCharGemInstanceSweepReward|1:AwardItems:r>ItemTpl,2:Exp:u,3:DoubleItems:r>ItemTpl,2047:NextPackage:b\nCharGemInstanceSweepResp|1:Change:>ChangeInfo,2:Rewards:r>CharGemInstanceSweepReward,2047:NextPackage:b\nCha" +
    "rGemRefreshReq|1:CharId:u,2:SlotId:u,3:GemIndex:u,4:LockAttrs:ru,2047:NextPackage:b\nCharGemRefreshResp|1:Attributes:ru,2:ChangeInfo:>ChangeInfo,3:OverlockCount:ru,2047:NextPackage:b\nCharGemRenamePresetReq|1:CharId:u,2:PresetId:u,3:NewName:s,2047:NextPackage:b\nCharGemReplaceAttributeReq|1:CharId:u,2:SlotId:u,3:GemIndex:u,2047:NextPackage:b\nCharGemUpdateGemLockStatusReq|1:CharId:u,2:SlotId:u,3:GemIn" +
    "dex:u,4:Lock:u,2047:NextPackage:b\nCharGemOverlockReq|1:CharId:u,2:SlotId:u,3:GemIndex:u,4:AttrIndex:u,2047:NextPackage:b\nCharGemOverlockRevertReq|1:CharId:u,2:SlotId:u,3:GemIndex:u,4:AttrIndex:u,2047:NextPackage:b\nCharGemUsePresetReq|1:CharId:u,2:PresetId:u,2047:NextPackage:b\nCharSkillUpgradeReq|1:CharId:u,2:Index:u,2047:NextPackage:b\nCharSkinSetReq|1:CharId:u,2:SkinId:u,2047:NextPackage:b\nCharUpg" +
    "radeReq|1:CharId:u,2:Items:r>ItemTpl,2047:NextPackage:b\nCharUpgradeResp|1:Level:u,2:Exp:u,3:Change:>ChangeInfo,2047:NextPackage:b\nDailyInstanceApplyReq|1:Id:u,2:RewardType:u,3:Build:>UseBuild,2047:NextPackage:b\nDailyInstanceRaidReq|1:Id:u,2:RewardType:u,4:Times:u,15:Events:>Events,2047:NextPackage:b\nDailyInstanceReward|1:Select:r>Item,2:DoubleItems:r>Item,15:Exp:u,2047:NextPackage:b\nDailyInstanceR" +
    "aidResp|1:Rewards:r>DailyInstanceReward,2:Change:>ChangeInfo,2047:NextPackage:b\nDailyInstanceSettleReq|1:Star:u,15:Events:>Events,2047:NextPackage:b\nDailyInstanceSettleResp|1:Select:r>Item,2:First:r>Item,3:Exp:u,4:DoubleItems:r>Item,15:Change:>ChangeInfo,2047:NextPackage:b\nDictRewardReq|1:TabId:u,2:Index:u,2047:NextPackage:b\nDiscAllLimitBreakResp|1:LimitBreaks:r>DiscLimitBreakChange,2:Change:>Chan" +
    "geInfo,2047:NextPackage:b\nDiscLimitBreakChange|1:Id:u,2:Star:u,2047:NextPackage:b\nDiscLimitBreakReq|1:Id:u,2:Qty:u,2047:NextPackage:b\nDiscLimitBreakResp|1:Star:u,2:Change:>ChangeInfo,2047:NextPackage:b\nDiscPromoteReq|1:Id:u,2047:NextPackage:b\nDiscPromoteResp|1:Phase:u,2:Change:>ChangeInfo,2047:NextPackage:b\nDiscReadRewardReceiveReq|1:Id:u,2:ReadType:u,2047:NextPackage:b\nDiscStrengthenReq|1:Id:u,2:" +
    "Items:r>ItemInfo,2047:NextPackage:b\nDiscStrengthenResp|1:Level:u,2:Exp:u,3:Change:>ChangeInfo,2047:NextPackage:b\nDormInfo|1:SkinList:ru,2:LayoutList:ru,3:SceneList:ru,2047:NextPackage:b\nDormRoomInfo|1:DormRoomId:u,2:FurnitureList:r>FurnitureInfo,3:RoleList:r>DormRoleInfo,4:DiscId:u,5:RoomName:s,6:RoomScene:u,7:RestNameTime:l,2047:NextPackage:b\nFurnitureInfo|1:FurnitureId:u,2:X:u,3:Y:u,4:Z:u,5:Rota" +
    "tion:u,2047:NextPackage:b\nDormRoleInfo|1:RoleId:u,2:IsVisit:u,3:IsInvitationRole:u,2047:NextPackage:b\nFurniturePresetInfo|1:DormType:u,2:FurnitureList:r>FurnitureInfo,3:BuildId:u,4:BuildName:s,15:CreateTime:l,2047:NextPackage:b\nDormBagInfo|1:ItemTplInfo:>ItemTpl,2047:NextPackage:b\nInvitationRoleInfo|1:RoleId:u,2047:NextPackage:b\nDormInfoData|1:DormName:s,2:LikeNum:u,3:DayVisitNum:u,4:VisitTotalNum" +
    ":u,5:rewardIds:ru,6:TaskGroup:>UI32V,7:AchievementList:r>AchievementInfo,8:RestNameTime:l,2047:NextPackage:b\nDormFriendDetail|1:uid:u,2:LikeNum:u,3:IsLike:u,4:DormName:s,5:CollectionValue:u,2047:NextPackage:b\nRoleInteraction|1:DormRoomId:u,2:RoleId:u,2047:NextPackage:b\nAffinityData|1:AffinityInfo:>AffinityInfo,2:ItemInfo:>ItemTpl,2047:NextPackage:b\nDormFriendInfo|1:DormName:s,2047:NextPackage:b\nDo" +
    "rmAffinityGiftInfo|1:RoleId:u,2:SendGiftCnt:u,2047:NextPackage:b\ntest|1:Test:u,2047:NextPackage:b\nDormRoomBGMInfo|1:DormRoomId:u,2:DiscId:u,2047:NextPackage:b\nDormRoomUnlock|1:DormRoomId:u,2:ChangeInfo:>ChangeInfo,2047:NextPackage:b\nDormChangeDataInfo|1:DormName:s,2:LikeNum:u,3:DayVisitNum:u,4:VisitTotalNum:u,2047:NextPackage:b\nDormHot|1:CollectionValue:u,2:Newbies:r>NewbieInfo,2047:NextPackage:b\n" +
    "AchievementComplete|1:ChangeInfo:>ChangeInfo,2:AchievementList:r>AchievementInfo,2047:NextPackage:b\nAchievementInfo|1:AchievementId:u,2:CompleteTime:l,2047:NextPackage:b\nDormAchievementRewardReceiveReq|1:AchievementIds:ru,2047:NextPackage:b\nDormAffinityGiftSendReq|1:CharId:u,2:DormRoomId:u,3:Items:r>ItemTpl,2047:NextPackage:b\nDormAffinityGiftSendResp|1:Info:>AffinityInfo,2:Change:>ChangeInfo,3:Sen" +
    "dGiftCnt:u,2047:NextPackage:b\nDormFriendLikeReq|1:FriendId:u,2047:NextPackage:b\nDormFriendListResp|1:Friends:r>DormFriendDetail,2047:NextPackage:b\nDormFriendVisitReq|1:FriendId:u,2047:NextPackage:b\nDormFriendVisitResp|1:DormList:r>DormRoomInfo,3:DormInfo:>DormFriendInfo,2047:NextPackage:b\nDormBagListResp|1:DormBagList:r>DormBagInfo,2047:NextPackage:b\nDormFurniturePresetListResp|1:PresetList:r>Furn" +
    "iturePresetInfo,2:Num:u,2047:NextPackage:b\nDormFurnitureSaveReq|1:DormRoomId:u,2:FurniturePosInfoList:r>FurnitureInfo,3:BuildId:u,2047:NextPackage:b\nDormChangeDataResp|1:DormChangeData:>DormChangeDataInfo,2047:NextPackage:b\nDormInfoListResp|1:DormList:r>DormRoomInfo,2:DormInfo:>DormInfoData,3:ReceivedRewardIds:ru,4:InteractionRoleIds:ru,5:AffinityGiftRoleInfos:r>DormAffinityGiftInfo,2047:NextPacka" +
    "ge:b\nDormInvitationRoleReq|1:DormRoomId:u,2:InvitationRoleList:r>InvitationRoleInfo,2047:NextPackage:b\nDormLayoutRewardReceiveReq|1:LayoutIds:ru,2047:NextPackage:b\nDormRewardReceiveReq|1:rewardIds:ru,2047:NextPackage:b\nDormRoleInteractionReq|1:RoleInteractions:r>RoleInteraction,2047:NextPackage:b\nDormRoleInteractionResp|1:InfoList:r>AffinityData,2:Change:>ChangeInfo,2047:NextPackage:b\nDormRoomBGMR" +
    "eq|1:BGMList:r>DormRoomBGMInfo,2047:NextPackage:b\nEnergyBuyResp|1:Count:u,2:Change:>ChangeInfo,2047:NextPackage:b\nFriendAddReq|1:UId:u,2047:NextPackage:b\nFriendAddAgreeReq|1:UId:u,2047:NextPackage:b\nFriendAddAgreeResp|1:Friend:>Friend,2047:NextPackage:b\nFriendAllAgreeResp|1:Limit:u,2:Friends:r>Friend,3:Invites:r>Friend,2047:NextPackage:b\nFriendDeleteReq|1:UId:u,2047:NextPackage:b\nFriendInvitesDele" +
    "teReq|1:UIds:ru,2047:NextPackage:b\nFriendListGetResp|1:Friends:r>FriendDetail,2:Invites:r>Friend,3:ReceiveEnergyCnt:u,2047:NextPackage:b\nFriendNameSearchReq|1:Name:s,2047:NextPackage:b\nFriendNameSearchResp|1:Friends:r>Friend,2047:NextPackage:b\nFriendReceiveEnergyReq|1:UIds:ru,2047:NextPackage:b\nFriendReceiveEnergyResp|1:UIds:ru,2:Change:>ChangeInfo,3:ReceiveEnergyCnt:u,2047:NextPackage:b\nFriendRec" +
    "ommendationGetResp|1:Friends:r>Friend,2047:NextPackage:b\nFriendSendEnergyReq|1:UIds:ru,2047:NextPackage:b\nFriendSendEnergyResp|1:UIds:ru,2047:NextPackage:b\nFriendStarSetReq|1:UIds:ru,2:Star:u,2047:NextPackage:b\nFriendUIdSearchReq|1:Id:u,2047:NextPackage:b\nFriendUIdSearchResp|1:Friend:>Friend,2047:NextPackage:b\nGachaHistory|1:Ids:ru,2:Time:l,3:Gid:u,2047:NextPackage:b\nGachaHistories|1:List:r>GachaH" +
    "istory,2047:NextPackage:b\nGachaInfo|1:Id:u,2:DaysCount:u,3:AupMissTimes:u,4:AMissTimes:u,10:RewardsRecords:b,11:ReveFirstTenReward:u,12:RecvGuaranteeReward:u,13:GachaTotalTimes:u,14:TotalTimes:u,15:AupGuaranteeTimes:u,2047:NextPackage:b\nGachaInformationResp|1:Information:r>GachaInfo,2047:NextPackage:b\nGachaNewbieInfo|1:Id:u,2:Receive:u,3:Times:u,14:Cards:r>UI32s,15:Temp:>UI32s,2047:NextPackage:b\nG" +
    "achaNewbieInfoResp|1:List:r>GachaNewbieInfo,2047:NextPackage:b\nGachaNewbieObtainReq|1:Id:u,2:Idx:u,2047:NextPackage:b\nGachaNewbieSaveReq|1:Id:u,2:Idx:u,2047:NextPackage:b\nGachaNewbieSpinResp|1:Cards:ru,2047:NextPackage:b\nGachaSpinReq|1:Id:u,2:Mode:u,15:Check:r>ItemTpl,2047:NextPackage:b\nGachaSpinResp|1:Cards:r>GachaCard,2:Change:>ChangeInfo,3:Time:l,10:AMissTimes:u,11:GachaTotalTimes:u,12:TotalTim" +
    "es:u,13:AupGuaranteeTimes:u,14:AupMissTimes:u,15:DaysCount:u,2047:NextPackage:b\nGachaCard|1:Card:>ItemTpl,2:Rewards:r>ItemTpl,2047:NextPackage:b\nGachaSpinSyncResp|2:Res:r>Res,3:Items:r>Item,2047:NextPackage:b\nSudoCommand|1:Action:s,2:Args:s,2047:NextPackage:b\nGuideMissionInfo|1:Chapters:r>GuideMissionChapter,2047:NextPackage:b\nGuideMissionChapter|1:Id:u,2:UnlockTime:l,3:Quests:>Quests,4:Done:u,204" +
    "7:NextPackage:b\nGuideMissionQuestRewardReceiveReq|1:QuestId:u,2:Group:u,2047:NextPackage:b\nIKEReq|1:ProtoVersion:i,2:ClientTs:l,3:PubKey:b,2047:NextPackage:b\nIKEResp|1:Token:s,2:Cipher:i,3:ServerTs:l,4:PubKey:b,2047:NextPackage:b\nInfinityTowerApplyReq|1:LevelId:u,2:Build:>UseBuild,2047:NextPackage:b\nInfinityTowerDailyRewardReceiveResp|1:Show:r>ItemTpl,2:Change:>ChangeInfo,2047:NextPackage:b\nInfini" +
    "tyTowerInfoResp|1:BountyLevel:u,2:PlotsIds:ru,3:Infos:r>InfinityTowerLevelInfo,2047:NextPackage:b\nInfinityTowerPlotRewardReceiveResp|1:Show:r>ItemTpl,2:Change:>ChangeInfo,2047:NextPackage:b\nInfinityTowerSettleReq|1:Value:u,8:Events:>Events,2047:NextPackage:b\nInfinityTowerSettleResp|1:NextLevelId:u,2:Show:r>ItemTpl,3:Change:>ChangeInfo,6:BountyLevel:u,7:Value:u,2047:NextPackage:b\nItemProductReq|1:I" +
    "d:u,2:Num:u,2047:NextPackage:b\nPickItem|1:Id:u,2:Tid:u,3:SelectTid:u,4:Qty:u,2047:NextPackage:b\nPickItems|1:List:r>PickItem,2047:NextPackage:b\nUseItem|1:List:r>ItemInfo,2047:NextPackage:b\nItemUseReq|1:Pick:>PickItems,2:Use:>UseItem,2047:NextPackage:b\nPickItemReq|1:List:r>PickItem,2047:NextPackage:b\nGrowthStep|1:Product:>ItemProductReq,2:Pick:>PickItemReq,2047:NextPackage:b\nItemGrowthReq|1:List:r>G" +
    "rowthStep,2047:NextPackage:b\nJointDrill2ApplyReq|1:LevelId:u,2:BuildId:u,3:BossHps:r>JointDrillBossHp,4:BossHpMaxes:r>JointDrillBossHp,5:Simulate:u,2047:NextPackage:b\nJointDrill2ApplyResp|1:Change:>ChangeInfo,2:StarTime:l,2047:NextPackage:b\nJointDrill2ContinueReq|1:BuildId:u,2047:NextPackage:b\nJointDrill2GiveUpReq|1:Floor:u,2:Time:u,3:Damage:u,4:BossHps:r>JointDrillBossHp,5:Record:b,2047:NextPacka" +
    "ge:b\nJointDrill2SettleReq|1:Time:u,2:Damage:u,3:Sample:>TravelerDuelBattleSamples,4:Checksum:u,7:Events:>Events,2047:NextPackage:b\nJointDrill2SyncReq|1:Floor:u,2:Time:u,3:Damage:u,4:BossHps:r>JointDrillBossHp,5:BossHpMaxes:r>JointDrillBossHp,6:Record:b,2047:NextPackage:b\nJointDrillApplyReq|1:LevelId:u,2:BuildId:u,3:BossHp:u,4:BossHpMax:u,5:Simulate:u,2047:NextPackage:b\nJointDrillApplyResp|1:Change" +
    ":>ChangeInfo,2:StarTime:l,2047:NextPackage:b\nJointDrillContinueReq|1:BuildId:u,2047:NextPackage:b\nJointDrillGiveUpReq|1:Floor:u,2:Time:u,3:Damage:u,4:BossHp:u,5:Record:b,2047:NextPackage:b\nJointDrillRankInfo|1:LastRefreshTime:l,2:Self:>JointDrillRankData,3:Rank:r>JointDrillRankData,4:Total:u,2047:NextPackage:b\nJointDrillRankChar|1:Id:u,2:Level:u,2047:NextPackage:b\nJointDrillRankTeam|1:Chars:r>Join" +
    "tDrillRankChar,2:BuildScore:u,3:Damage:u,4:Time:u,5:Discs:ru,6:Potentials:r>BuildPotential,7:Notes:r>ItemTpl,8:ActiveSecondaryIds:ru,2047:NextPackage:b\nJointDrillRankData|1:Id:u,2:NickName:s,3:WorldClass:u,4:HeadIcon:u,5:Score:u,6:Rank:u,7:TitlePrefix:u,8:TitleSuffix:u,9:Honors:r>HonorInfo,10:Teams:r>JointDrillRankTeam,2047:NextPackage:b\nJointDrillRankTeams|1:Teams:r>JointDrillRankTeam,2047:NextPa" +
    "ckage:b\nJointDrillSettleReq|1:Time:u,2:Damage:u,3:Sample:>TravelerDuelBattleSamples,4:Checksum:u,7:Events:>Events,2047:NextPackage:b\nJointDrillSweepReq|1:LevelId:u,2:Count:u,2047:NextPackage:b\nJointDrillSweepResp|1:Change:>ChangeInfo,2:Rewards:r>ItemTpls,3:Score:u,2047:NextPackage:b\nJointDrillSyncReq|1:Floor:u,2:Time:u,3:Damage:u,4:BossHp:u,5:BossHpMax:u,6:Record:b,2047:NextPackage:b\nMailPinReques" +
    "t|1:Id:u,2:Flag:u,3:Pin:u,2047:NextPackage:b\nMailRecvResp|1:Ids:ru,2:Items:>ChangeInfo,2047:NextPackage:b\nMailRemoveResp|1:Ids:ru,2047:NextPackage:b\nMallActivityInfo|1:Id:s,2:Purchased:u,2047:NextPackage:b\nMallActivityList|1:List:r>MallActivityInfo,2047:NextPackage:b\nGemInfo|1:Id:s,2:Maiden:u,2047:NextPackage:b\nMallGemList|1:List:r>GemInfo,2047:NextPackage:b\nOrderInfo|1:Id:s,2:ExtraData:s,3:Notify" +
    "Url:s,2047:NextPackage:b\nMonthlyCardInfo|1:Id:s,2:Remaining:u,3:Received:u,2047:NextPackage:b\nMallMonthlyCardList|1:List:r>MonthlyCardInfo,2047:NextPackage:b\nPackageInfo|1:Id:s,2:Stock:u,3:RefreshTime:l,2047:NextPackage:b\nMallPackageList|1:List:r>PackageInfo,2047:NextPackage:b\nMallPackageOrder|1:Change:>ChangeInfo,2:Order:>OrderInfo,2047:NextPackage:b\nProductInfo|1:Id:s,2:Stock:i,3:RefreshTime:l,2" +
    "047:NextPackage:b\nMallShopProductList|1:List:r>ProductInfo,2047:NextPackage:b\nMallShopOrderReq|1:Id:s,2:Qty:u,2047:NextPackage:b\nMilkoutCollect|1:Id:u,2:Count:u,2047:NextPackage:b\nMilkoutSettleReq|1:ActivityId:u,2:LevelId:u,3:Seconds:u,4:MonsterDefeatCount:u,5:Win:u,6:CharId:u,7:Count:u,8:RemainHP:u,9:Score:u,10:DropCollect:r>MilkoutCollect,2047:NextPackage:b\nSoldierInfo|1:Meta:>SoldierMeta,2:Node" +
    ":>SoldierNode,3:Bag:>SoldierBag,4:Cases:r>SoldierCase,5:Effects:r>SoldierEffectInfo,6:Progress:r>SoldierBuffProgress,2047:NextPackage:b\nSoldierMeta|1:Id:u,2:Hp:u,3:DataLen:u,4:ClientData:s,5:DataVersion:u,6:WinningStreak:u,7:LosingStreak:u,8:ShopLevel:u,9:ShopExp:u,10:TracePartnerTypes:ru,2047:NextPackage:b\nSoldierNode|1:Data:>SoldierNodeData,2047:NextPackage:b\nSoldierNodeData|1:StageId:u,2:NodeId" +
    ":u,3:Type:u,2047:NextPackage:b\nSoldierBag|1:Deploy:>SoldierDeploy,2:Res:r>SoldierRes,3:Buffs:r>SoldierBuff,2047:NextPackage:b\nSoldierDeploy|1:Version:u,2:Chess:r>SoldierChess,2047:NextPackage:b\nSoldierRes|1:Tid:u,2:Qty:i,2047:NextPackage:b\nSoldierCase|1:Id:u,2:SelectCard:>SelectCardData,3:ShopCase:>ShopCaseData,4:FightCase:>FightCaseData,5:BattleCase:>SoldierBattleCaseData,6:EventSettlementOfDispu" +
    "te:>EventSettlementOfDisputeCaseData,7:EventSettlementOfDisputeBattle:>EventSettlementOfDisputeBattleCaseData,8:SelectBossAbilityCase:>SelectBossAbilityCaseData,9:CheckStageCase:>CheckStageCaseData,10:StoryEventOfPersonalityCase:>SoldierStoryEventOfPersonalityCaseData,11:StoryEventOfCostlyCase:>SoldierStoryEventOfCostlyCaseData,14:DeployOptCase:>DeploySyncCaseData,15:ClientEventCase:>ClientEventCa" +
    "seData,2047:NextPackage:b\nSoldierChess|1:UID:u,2:Tid:u,3:Star:u,4:Slot:u,2047:NextPackage:b\nSoldierChessList|1:ChessList:r>SoldierChess,2047:NextPackage:b\nSoldierTransform|1:Consume:r>SoldierChess,2:Obtain:r>SoldierChess,3:Update:r>SoldierChess,2047:NextPackage:b\nSoldierChessChange|1:Transforms:r>SoldierTransform,2:BaseVersion:u,3:NextVersion:u,2047:NextPackage:b\nSoldierBuff|1:BindId:u,2:EffectGro" +
    "up:u,3:Type:u,4:Action:u,5:BuffIds:ru,2047:NextPackage:b\nSoldierBuffProgress|1:BuffId:u,2:Removed:u,3:Type:u,4:Cur:u,5:Max:u,2047:NextPackage:b\nSoldierSyncData|1:Hp:u,2:Level:u,3:Exp:u,4:WinningStreak:u,5:LosingStreak:u,2047:NextPackage:b\nSoldierGoods|1:Id:u,2:Star:u,3:Price:u,2047:NextPackage:b\nSelectBossAbilityCaseData|2047:NextPackage:b\nShopCaseData|1:Level:u,2:Exp:u,3:Goods:r>SoldierGoods,4:Ra" +
    "rityUp:ru,5:Lock:u,6:Free:u,7:ReRollPrice:u,8:DisableRefresh:u,9:DisablePurchase:u,10:PurchaseExpPrice:u,11:TempFree:u,2047:NextPackage:b\nSelectCardData|1:Ids:ru,2:ReRoll:u,2047:NextPackage:b\nFightCaseData|2047:NextPackage:b\nSoldierBattleCaseData|1:FloorId:u,2047:NextPackage:b\nEventSettlementOfDisputeCaseData|1:Ids:ru,2047:NextPackage:b\nEventSettlementOfDisputeBattleCaseData|1:BattleId:u,2:FloorId" +
    ":u,2047:NextPackage:b\nCheckStageCaseData|1:FloorId:u,2047:NextPackage:b\nClientEventCaseData|2047:NextPackage:b\nDeploySyncCaseData|2047:NextPackage:b\nInteractSelectBossAbilityReq|1:AbilityId:u,2047:NextPackage:b\nInteractShopReq|1:Purchase:u,2:Sell:>SoldierChess,3:Refresh:u,4:Upgrade:u,5:Lock:u,2047:NextPackage:b\nInteractShopResp|1:Goods:>SoldierChess,2:ShopData:>ShopCaseData,3:Upgrade:>UpgradeResul" +
    "t,4:Res:>SoldierRes,5:Succeed:u,2047:NextPackage:b\nUpgradeResult|1:Level:u,2:Exp:u,3:RarityUp:ru\nInteractFightReq|2047:NextPackage:b\nInteractSoldierBattleReq|1:DataLen:u,2:ClientData:s,3:DataVersion:u,4:ChessSkillAddGold:u,5:Events:>Events,13:Victory:>VictoryData,14:Defeat:u,2047:NextPackage:b\nInteractSoldierBattleResp|1:BaseReward:u,2:WinningStreak:u,3:LosingStreak:u,4:Interest:u,2047:NextPackage" +
    ":b\nInteractEventSettlementOfDisputeReq|1:Index:u,2047:NextPackage:b\nInteractEventSettlementOfDisputeBattleReq|1:DataLen:u,2:ClientData:s,3:DataVersion:u,4:ChessSkillAddGold:u,5:Events:>Events,13:Victory:>VictoryData,14:Defeat:u,2047:NextPackage:b\nInteractEventSettlementOfDisputeBattleResp|1:Coin:u,2:Chess:r>SoldierChess,3:BaseReward:u,4:Interest:u,2047:NextPackage:b\nInteractSoldierSelectReq|1:Inde" +
    "x:u,2:ReRoll:u,2047:NextPackage:b\nInteractSoldierSelectResp|1:Resp:>Success,2:SelectCard:>SelectCardData,2047:NextPackage:b\nInteractCheckStageSettleReq|1:DpsId:u,2:TimeId:u,2047:NextPackage:b\nInteractCheckStageSettleResp|1:DpsScore:u,2:TimeScore:u,2047:NextPackage:b\nInteractClientEventReq|1:DataLen:u,2:ClientData:s,3:DataVersion:u,2047:NextPackage:b\nSoldierSettleDataResp|1:Result:u,2:PassedNode:u," +
    "3:RemainingHp:u,4:CheckStageDps:u,5:CheckStageTime:u,6:ChessTotalCost:u,7:GetSchedule:u,8:GetTechPoint:u,9:GetGradeExp:u,10:CurGradeChallengeId:u,11:CurGradeExp:u,12:EndingId:u,13:TotalCoinQty:u,15:Change:>ChangeInfo,2047:NextPackage:b\nInteractDeploySyncReq|1:DeployVersion:u,2:Sync:>SyncChessAction,3:Move:>MoveChessAction,2047:NextPackage:b\nSyncChessAction|2047:NextPackage:b\nMoveChessAction|1:UID:" +
    "u,2:Slot:u,2047:NextPackage:b\nInteractDeploySyncResp|1:Succeed:>Nil,2:Deploy:>SoldierDeploy,2047:NextPackage:b\nSoldierEffect|1:Id:u,2:Tid:u,3:BuffId:u,6:LeftmostChange:>SoldierEffectLeftmostWaitingChessChange,7:BecomeAnother:>SoldierShopRandomChessBecomeAnotherHigherCost,8:PartnerAdditional:>SoldierEffectPartnerAdditional,9:PartnerActivateAdditional:>SoldierEffectPartnerActivateAdditional,10:NodeT" +
    "ypeModify:>SoldierNodeTypeModify,11:ClientAttr:>SoldierClientEffectAttr,12:RefreshState:>SoldierShopRefreshState,13:PurchaseState:>SoldierShopPurchaseState,14:FreeState:>SoldierShopFreeState,15:Rarity:>SoldierShopRarity,16:PurchaseExpDiscount:>SoldierShopPurchaseExpDiscount,17:ShowChess:>SoldierEffectAddChess,18:ClientHarvest:>SoldierEffectClientHarvest,19:Interest:>SoldierEffectInterest,20:CardRe" +
    "Roll:>SoldierEffectCardReRoll,21:DiceAddPoint:>SoldierEffectDiceAddPoint,22:TempFree:>SoldierShopTempFreeState,2047:NextPackage:b\nSoldierEffectInfo|1:PartnerAdditional:>SoldierEffectPartnerAdditional,2:PartnerActivateAdditional:>SoldierEffectPartnerActivateAdditional,3:ClientHarvest:>SoldierEffectClientHarvest,4:Interest:>SoldierEffectInterest,5:CardReRoll:>SoldierEffectCardReRoll,10:NodeTypeModif" +
    "y:>SoldierNodeTypeModify,11:ClientAttr:>SoldierClientEffectAttr,12:DiceAddPoint:>SoldierEffectDiceAddPoint,2047:NextPackage:b\nSoldierEffectLeftmostWaitingChessChange|1:UID:u,2:Chess:>SoldierChess,2047:NextPackage:b\nSoldierShopRandomChessBecomeAnotherHigherCost|1:GoodsIdx:u,2:Goods:>SoldierGoods,2047:NextPackage:b\nSoldierEffectPartnerAdditional|1:Status:u,2:PartnerType:u,3:Additional:u,2047:NextPac" +
    "kage:b\nSoldierEffectPartnerActivateAdditional|1:Status:u,2:Additional:u,2047:NextPackage:b\nSoldierNodeTypeModify|2:FromNodeType:u,3:ToNodeType:u,4:EventPoolId:u,2047:NextPackage:b\nSoldierClientEffectAttr|1:Status:u,2:Source:>SoldierEffectSource,3:Values:ru,2047:NextPackage:b\nSoldierEffectSource|1:Id:u,2:Tid:u,3:BuffId:u,2047:NextPackage:b\nSoldierShopRefreshState|1:DisableRefresh:u,2047:NextPackage" +
    ":b\nSoldierShopPurchaseState|1:DisablePurchase:u,2047:NextPackage:b\nSoldierShopFreeState|1:Status:u,2:Free:u,2047:NextPackage:b\nSoldierShopTempFreeState|1:Status:u,2:Free:u,2047:NextPackage:b\nSoldierShopRarity|1:Status:u,2:Rarity:u,2047:NextPackage:b\nSoldierShopPurchaseExpDiscount|1:Status:u,2:Discount:u,2047:NextPackage:b\nSoldierEffectAddChess|1:Chess:r>SoldierChess,2047:NextPackage:b\nSoldierEffec" +
    "tClientHarvest|1:Status:u,2:Count:u,2047:NextPackage:b\nSoldierEffectInterest|1:Status:u,2:Limit:u,2047:NextPackage:b\nSoldierEffectCardReRoll|1:Status:u,2:Count:u,2047:NextPackage:b\nSoldierEffectDiceAddPoint|1:Status:u,2:Source:>SoldierEffectSource,3:Point:u,2047:NextPackage:b\nSoldierSeasonInfo|1:SeasonId:u,2:RewardLv:u,3:RewardExp:u,4:CurGradeChallengeId:u,5:CurGradeExp:u,6:CurRewardLv:u,7:Newbies" +
    ":r>NewbieInfo,2047:NextPackage:b\nSoldierEventChessReward|1:Tid:u,2:Star:u,3:Qty:i,2047:NextPackage:b\nSoldierEventResRewards|1:ResRewards:r>SoldierRes,2047:NextPackage:b\nSoldierEventChessRewards|1:ChessRewards:r>SoldierEventChessReward,2047:NextPackage:b\nSoldierStoryEventRewardShow|1:RewardType:u,2:Resource:>SoldierEventResRewards,3:Chess:>SoldierEventChessRewards,4:Hp:i,5:Ids:>UI32s,6:Nil:>Nil,204" +
    "7:NextPackage:b\nSoldierStoryEventOption|1:PersonalityOptionId:u,2:Rewards:r>SoldierStoryEventRewardShow,3:Select:u,2047:NextPackage:b\nSoldierStoryEventOptions|1:Options:r>SoldierStoryEventOption,2047:NextPackage:b\nSoldierStoryEventOfPersonalityCaseData|1:PersonalityStoryId:u,2:Options:>SoldierStoryEventOptions,3:Index:u,4:DicePoint:u,5:TwoDice:u,6:PreOptionId:u,2047:NextPackage:b\nSoldierStoryEvent" +
    "OfCostlyCaseData|1:PersonalityStoryId:u,2:Options:>SoldierStoryEventOptions,6:PreOptionId:u,2047:NextPackage:b\nInteractStoryEventOfPersonalitySelectReq|1:Index:u,2:ThrowDice:u,2047:NextPackage:b\nInteractStoryEventOfPersonalitySelectResp|1:Success:>Nil,2:Reward:>OptionReward,2047:NextPackage:b\nOptionReward|1:Point:u,2:Result:u,3:Rewards:r>SoldierStoryEventEffectReward,4:TwoDicePoint:ru\nInteractStor" +
    "yEventOfCostlySelectResp|1:Rewards:r>SoldierStoryEventEffectReward,2047:NextPackage:b\nSoldierStoryEventEffectReward|1:RewardType:u,2:Hp:i,3:Res:>SoldierEventResRewards,4:ChessList:>SoldierChessList,5:CardIds:>UI32s,6:CardEffectIds:>UI32s,7:NextOptions:>SoldierStoryEventOptions,2047:NextPackage:b\nNewAgent|1:Ids:ru,2047:NextPackage:b\nSigninRewardUpdate|1:Index:u,2:Change:>ChangeInfo,6:Switch:u,2047:" +
    "NextPackage:b\nOrderStateChange|1:OrderId:s,2:Store:u,2047:NextPackage:b\nStarTowerBookPotentialChange|1:CharPotentials:r>StarTowerBookCharPotential,2:CharIds:ru,2047:NextPackage:b\nStarTowerBookEventChange|1:EventIds:ru,2047:NextPackage:b\nSkin|1:New:>UI32,2:Duplicated:>Transform,2047:NextPackage:b\nSkinChange|1:CharId:u,2:SkinId:u,2047:NextPackage:b\nMonthlyCardRewards|1:Id:u,2:Change:>ChangeInfo,3:En" +
    "dTime:l,4:Rewards:r>ItemTpl,5:Remaining:u,6:Switch:u,2047:NextPackage:b\nTowerBookFateCardCollectNotify|1:Cards:ru,2047:NextPackage:b\nTowerBookFateCardRewardChangeNotify|1:List:ru,2:Option:u,2047:NextPackage:b\nHonorChangeNotify|1:Honors:r>HonorInfo,2047:NextPackage:b\nNoticeChangeNotify|1:Content:s,2:Channel:ri,3:StartTime:l,4:EndTime:l,5:Interval:i,6:Duration:i,7:IsStop:u,2047:NextPackage:b\nPlayerH" +
    "eadIconChangeNotify|1:Set:u,2:Del:u,2047:NextPackage:b\nActivityMiningEnterLayerNotify|1:Layer:>MiningLayer,2:MiningChangeInfo:>MiningChangeInfo,2047:NextPackage:b\nOrderCollected|1:Orders:r>OrderStateChange,2047:NextPackage:b\nMilkoutCharacterUnlockNotify|1:ActivityId:u,2:CharId:u,2047:NextPackage:b\nActivityDoubleRewardTimesNotify|1:ActivityId:u,2:UseTimes:u,3:ReturneeTimes:u,2047:NextPackage:b\nGmWo" +
    "rldClass|1:FinalClass:u,2:LastExp:i,3:Stage:u,15:RewardsFlag:b,2047:NextPackage:b\nGmClearAllVampireSurvivor|1:Records:r>VampireSurvivorLevel,2047:NextPackage:b\nStarTowerSubNoteSkillInfo|1:SubNoteSkillInfo:r>StageFloorNum,2047:NextPackage:b\nFloorNum|1:Floor:u,2:Num:u\nStageFloorNum|1:StageId:u,2:Infos:r>FloorNum\nAgentInfos|1:Infos:r>AgentInfo,2047:NextPackage:b\nGmClearAllDailyInstance|1:DailyInstanc" +
    "es:r>DailyInstance,2:Change:>ChangeInfo,2047:NextPackage:b\nWeekBossLevels|1:WeekBossLevels:r>WeekBossLevel,2047:NextPackage:b\nGmClearAllRegionBossLevel|1:RegionBossLevels:r>RegionBossLevel,2:Change:>ChangeInfo,2047:NextPackage:b\nGmClearAllTravelerDue|1:Levels:r>TravelerDuelBossLevel,2:Change:>ChangeInfo,2047:NextPackage:b\nGmClearAllSkillInstance|1:SkillInstances:r>SkillInstance,2047:NextPackage:b\n" +
    "CharAffinity|1:Info:>AffinityInfo,2:Change:>ChangeInfo,2047:NextPackage:b\nGmSTClearAllStarTower|1:Ids:ru,2047:NextPackage:b\nSTAddTeamExpNtf|1:Level:u,2:Exp:u,3:Cases:r>StarTowerRoomCase,2047:NextPackage:b\nGmClearAllEquipmentInstance|1:EquipmentInstances:r>EquipmentInstance,2:Change:>ChangeInfo,2047:NextPackage:b\nGmAllInfinityTowerInfos|1:Infos:r>InfinityTowerLevelInfo,2047:NextPackage:b\nGmStory|1:" +
    "Evidences:ru,2:Stories:r>Story,3:Change:>ChangeInfo,2047:NextPackage:b\nGmHarmonySkillNotify|1:List:ru,2047:NextPackage:b\nGmTowerGrowthNodesNotify|1:Detail:ru,2047:NextPackage:b\nGmCharUpNotify|1:Char:>Char,2:Handbook:r>HandbookInfo,2047:NextPackage:b\nGmClearAllCharGemInstance|1:CharGemInstances:r>CharGemInstance,2047:NextPackage:b\nGmImportCharGemsNotify|1:CharId:u,2:CharGemSlots:r>CharGemSlot,3:Cha" +
    "rGemPresets:>CharGemPresets,2047:NextPackage:b\nGmClearAllActivityAvgNotify|1:Avgs:r>ActivityAvg,2047:NextPackage:b\nGmClearAllActivityLevelsNotify|1:levels:r>ActivityLevels,2047:NextPackage:b\nAssistAddBuildNotify|1:Change:>ChangeInfo,2:BuildRewards:r>ItemTpl,3:BuildInfo:>StarTowerBuildInfo,2047:NextPackage:b\nSoldierEffectNtf|1:Effects:r>SoldierEffect,2047:NextPackage:b\nGmClearAllActivityIceCreamLev" +
    "elsNotify|1:levels:r>ActivityIceCreamLevel,2047:NextPackage:b\nGmClearAllActivityMathParkourLevelsNotify|1:levels:r>ActivityMathParkourLevel,2047:NextPackage:b\nGmHandbookCompleteNotify|1:Handbook:r>HandbookInfo,2047:NextPackage:b\nNPCAffinityBookGetResp|1:Infos:r>NPCAffinity,2:Number:u,2047:NextPackage:b\nNPCAffinityPlotRewardReceiveResp|1:Show:r>ItemTpl,2:Change:>ChangeInfo,2047:NextPackage:b\nPhoneC" +
    "ontactsInfoResp|1:List:r>Contacts,2047:NextPackage:b\nPhoneContactsReportReq|1:ChatId:u,2:Options:ru,3:Process:u,4:End:u,2047:NextPackage:b\nPlayerBoardSetReq|1:Ids:ru,2047:NextPackage:b\nPlayerCharsShowReq|1:CharIds:ru,2047:NextPackage:b\nPlayerInfo|1:Acc:>AccInfo,2:Res:r>Res,3:Items:r>Item,4:Chars:r>Char,5:Formation:>TowerFormation,7:Energy:>EnergyInfo,8:WorldClass:>WorldClassInfo,9:Agent:>AgentData" +
    ",10:RglPassedIds:ru,11:Equipments:r>EquipmentInfo,12:RegionBossLevels:r>RegionBossLevel,13:Quests:>Quests,14:State:>StateInfo,15:SendGiftCnt:u,16:Board:ru,17:DatingCharIds:ru,18:Achievements:b,19:Handbook:r>HandbookInfo,20:SigninIndex:u,21:Titles:r>Title,22:DailyInstances:r>DailyInstance,23:Dictionaries:r>DictionaryTab,24:Activities:r>Activity,25:Phone:>PhoneInfo,26:TalentResetTime:l,27:EquipmentD" +
    "oubleCount:u,28:Discs:r>Disc,29:EquipmentInstances:r>EquipmentInstance,30:Story:>StoryInfo,31:VampireSurvivorRecord:>VampireSurvivorRecordInfo,32:DailyActiveIds:ru,33:TourGuideQuestGroup:u,34:SkillInstances:r>SkillInstance,35:WeekBossLevels:r>WeekBossLevel,36:CharGemInstances:r>CharGemInstance,37:TutorialLevels:r>TutorialLevel,38:WeeklyActiveIds:ru,39:Assists:r>AssistInfo,40:DailyMallRewardStatus:" +
    "u,41:ActivityHonors:r>ActivityHonor,42:Dorm:>DormHot,115:ActivityReturnee:>ActivityReturneeInfo,116:TowerTicketGrowthBonus:u,117:LastRead:>LastRead,118:HuntPermit:>TraceHuntItemInfo,119:TraceRequest:>TraceHuntItemInfo,120:PersonalityModels:r>ActivityPersonalityModel,121:NicknameResetTime:l,122:MusicInfo:l,123:HonorList:ru,124:Honors:r>HonorInfo,125:DailyShopRewardStatus:u,126:TowerTicket:u,127:Ser" +
    "verTs:l,2047:NextPackage:b\nPhoneInfo|1:NewMessage:u,2:ProgressMessage:u,2047:NextPackage:b\nDictionaryEntry|1:Index:u,2:Status:u,2047:NextPackage:b\nDictionaryTab|1:TabId:u,2:Entries:r>DictionaryEntry,2047:NextPackage:b\nEnergyInfo|1:Energy:>Energy,2:Count:u,2047:NextPackage:b\nWorldClassInfo|1:Cur:u,2:LastExp:i,3:Stage:u,2047:NextPackage:b\nAssistInfo|1:Attribute:u,2:Group:u,2047:NextPackage:b\nActivit" +
    "yReturneeInfo|1:Id:u,2:OpenTime:l,3:DoubleCount:u,4:ReunionReward:u,5:Avg:u,2047:NextPackage:b\nPlayerDestroy|1:NotifyUrl:s,2047:NextPackage:b\nPlayerFormationReq|1:Formation:>FormationInfo,2047:NextPackage:b\nPlayerHeadIconInfoResp|1:List:ru,2047:NextPackage:b\nPlayerHeadIconSetReq|1:HeadIcon:u,2047:NextPackage:b\nPlayerHonorEditReq|1:List:ru,2047:NextPackage:b\nLoginReq|1:Account:>Regular,2:Official:>" +
    "Official,3:OfficialOverseas:>OfficialOverseas,4:Token:s,11:Platform:u,12:Language:s,13:Channel:s,14:Device:s,15:Version:s,2047:NextPackage:b\nOfficial|1:Uid:u,2:Token:s,2047:NextPackage:b\nOfficialOverseas|1:Uid:s,2:Token:s,2047:NextPackage:b\nRegular|1:Name:s,2:Pass:s,2047:NextPackage:b\nLoginResp|1:Token:s,2047:NextPackage:b\nPlayerNameEditReq|1:Name:s,2047:NextPackage:b\nPlayerNameEditResp|1:Hashtag:" +
    "u,15:ResetTime:l,2047:NextPackage:b\nPing|2047:NextPackage:b\nPong|1:ServerTs:l,2047:NextPackage:b\nPlayerReg|1:Nickname:s,2:Gender:u,2047:NextPackage:b\nPlayerSignatureEditReq|1:Signature:s,2047:NextPackage:b\nPlayerSkinShowReq|1:SkinId:u,2047:NextPackage:b\nPlayerSurveyReq|1:SurveyId:l,2047:NextPackage:b\nPlayerSurveyResp|1:ActivityID:s,2:NotifyUrl:s,2047:NextPackage:b\nPlayerTitleEditReq|1:TitlePrefix:" +
    "u,2:TitleSuffix:u,2047:NextPackage:b\nPlayerWorldClassRewardReq|1:Class:u,2:Stage:u,2047:NextPackage:b\nPotentialPreselectionDeleteReq|1:Ids:ru,2047:NextPackage:b\nPotentialPreselectionImportReq|1:Name:s,2:Preference:u,3:CharPotentials:r>StarTowerBookCharPotential,2047:NextPackage:b\nPotentialPreselectionList|1:List:r>PotentialPreselection,2047:NextPackage:b\nPotentialPreselectionNameSetReq|1:Id:u,2:Na" +
    "me:s,2047:NextPackage:b\nPotentialPreselectionPreferenceSetReq|1:CheckInIds:ru,2:CheckOutIds:ru,2047:NextPackage:b\nPotentialPreselectionUpdateReq|1:Id:u,2:CharPotentials:r>StarTowerBookCharPotential,2047:NextPackage:b\nChars|1:List:r>Char,2047:NextPackage:b\nAssistGroupRewardResp|1:Change:>ChangeInfo,2:BuildRewards:r>ItemTpl,3:BuildInfo:>StarTowerBuildInfo,2047:NextPackage:b\nAssistQuestReceiveReq|1:G" +
    "roup:u,2:Quest:u,2047:NextPackage:b\nQuestDailyActiveRewardReceiveResp|1:ActiveIds:ru,2:Change:>ChangeInfo,2047:NextPackage:b\nQuestDormRewardReceiveSucceedAck|1:change_info:>ChangeInfo,2:TaskGroup:>UI32V,2047:NextPackage:b\nTourGuideQuestRewardResp|1:Rewards:r>ItemTpl,15:Change:>ChangeInfo,2047:NextPackage:b\nTourGuideQuestGroupRewardResp|1:Rewards:r>ItemTpl,15:Change:>ChangeInfo,2047:NextPackage:b\nQ" +
    "uestWeeklyActiveRewardReceiveResp|1:ActiveIds:ru,2:Change:>ChangeInfo,2047:NextPackage:b\nRedeemCodeResp|1:Items:r>ItemTpl,2:Change:>ChangeInfo,2047:NextPackage:b\nRegionBossLevelApplyReq|1:Id:u,2:Build:>UseBuild,2047:NextPackage:b\nRegionBossLevelSettleReq|1:Star:u,15:Events:>Events,2047:NextPackage:b\nRegionBossLevelSettleResp|1:First:u,2:ThreeStar:u,3:Change:>ChangeInfo,4:AwardItems:r>ItemTpl,5:Fir" +
    "stItems:r>ItemTpl,6:ThreeStarItems:r>ItemTpl,7:Exp:u,8:SurpriseItems:r>ItemTpl,9:DoubleItems:r>ItemTpl,2047:NextPackage:b\nRegionBossLevelSweepReq|1:Id:u,2:Times:u,15:Events:>Events,2047:NextPackage:b\nRegionBossLevelSweepResp|1:Change:>ChangeInfo,2:Rewards:r>RegionBossLevelSweepRewards,2047:NextPackage:b\nRegionBossLevelSweepRewards|1:AwardItems:r>ItemTpl,2:Exp:u,3:DoubleItems:r>ItemTpl,2047:NextPac" +
    "kage:b\nResidentShopGetReq|1:ShopIds:ru,2047:NextPackage:b\nResidentShopGetResp|1:Shops:r>ResidentShop,2047:NextPackage:b\nResidentShopPurchaseReq|1:ShopId:u,2:RefreshTime:l,3:GoodsId:u,4:Number:u,2047:NextPackage:b\nResidentShopPurchaseResp|1:IsRefresh:u,2:Shop:>ResidentShop,3:PurchasedNumber:u,4:Change:>ChangeInfo,2047:NextPackage:b\nScoreBossApplyReq|1:LevelId:u,2:BuildId:u,2047:NextPackage:b\nScoreB" +
    "ossInfo|1:ControlId:u,2:Score:u,3:Star:u,101:StarRewards:ru,102:Levels:r>ScoreBossLevel,2047:NextPackage:b\nScoreBossRankInfo|1:LastRefreshTime:l,2:Self:>ScoreBossRankData,3:Rank:r>ScoreBossRankData,4:Border:ru,5:Total:u,2047:NextPackage:b\nScoreBossRankChar|1:Id:u,2:Level:u,2047:NextPackage:b\nScoreBossRankTeam|1:BuildScore:u,2:Chars:r>ScoreBossRankChar,3:LevelScore:u,4:LevelId:u,5:Discs:ru,6:Potent" +
    "ials:r>BuildPotential,7:Notes:r>ItemTpl,8:ActiveSecondaryIds:ru,9:SkillScore:u,2047:NextPackage:b\nScoreBossRankData|1:Id:u,2:NickName:s,3:WorldClass:u,4:HeadIcon:u,5:Score:u,6:Rank:u,7:TitlePrefix:u,8:TitleSuffix:u,9:Teams:r>ScoreBossRankTeam,15:Honors:r>HonorInfo,2047:NextPackage:b\nScoreBossRankTeams|1:Teams:r>ScoreBossRankTeam,2047:NextPackage:b\nScoreBossSettleReq|1:Star:u,2:Score:u,3:sample:>Tr" +
    "avelerDuelBattleSamples,4:DamageScore:u,5:SkillScore:u,6:BossResultLevel:u,15:Events:>Events,2047:NextPackage:b\nScoreBossSettleResp|1:token:s,2:oldRank:u,3:newRank:u,2047:NextPackage:b\nScoreBossStarRewardReceiveReq|1:Star:u,2047:NextPackage:b\nSkillInstanceApplyReq|1:Id:u,2:Build:>UseBuild,2047:NextPackage:b\nSkillInstanceSettleReq|1:Star:u,15:Events:>Events,2047:NextPackage:b\nSkillInstanceSettleRes" +
    "p|1:First:u,2:ThreeStar:u,3:Change:>ChangeInfo,4:AwardItems:r>ItemTpl,5:FirstItems:r>ItemTpl,6:ThreeStarItems:r>ItemTpl,7:Exp:u,8:SurpriseItems:r>ItemTpl,9:DoubleItems:r>ItemTpl,2047:NextPackage:b\nSkillInstanceSweepReq|1:Id:u,2:Times:u,15:Events:>Events,2047:NextPackage:b\nSkillInstanceSweepResp|1:Change:>ChangeInfo,2:Rewards:r>SkillInstanceSweepRewards,2047:NextPackage:b\nSkillInstanceSweepRewards|" +
    "1:AwardItems:r>ItemTpl,2:Exp:u,3:DoubleItems:r>ItemTpl,2047:NextPackage:b\nSoldierApplyReq|1:SeasonId:u,2:GradeChallengeId:u,2047:NextPackage:b\nSoldierApplyResp|1:Info:>SoldierInfo,2:Chess:r>SoldierChess,3:CoinQty:u,4:Change:>ChangeInfo,2047:NextPackage:b\nSoldierBattleReportFavoriteList|1:Reports:r>SoldierBattleReport,2047:NextPackage:b\nSoldierBattleReportRecentList|1:Reports:r>SoldierBattleReport," +
    "2047:NextPackage:b\nSoldierInteractReq|1:Id:u,2:ShopReq:>InteractShopReq,3:FightReq:>InteractFightReq,4:BattleReq:>InteractSoldierBattleReq,5:SelectReq:>InteractSoldierSelectReq,6:EventSettlementOfDisputeReq:>InteractEventSettlementOfDisputeReq,7:EventSettlementOfDisputeBattleReq:>InteractEventSettlementOfDisputeBattleReq,8:SelectBossAbilityReq:>InteractSelectBossAbilityReq,9:CheckStageSettleReq:>I" +
    "nteractCheckStageSettleReq,10:StoryEventOfPersonalitySelectReq:>InteractStoryEventOfPersonalitySelectReq,14:DeploySyncReq:>InteractDeploySyncReq,15:ClientEventReq:>InteractClientEventReq,2047:NextPackage:b\nSoldierInteractResp|1:Id:u,2:Cases:r>SoldierCase,3:Change:>ChangeInfo,4:Node:>SoldierNodeData,5:SyncData:>SoldierSyncData,6:Effects:r>SoldierEffect,7:Settle:>SoldierSettleDataResp,8:ShopResp:>In" +
    "teractShopResp,9:BattleResp:>InteractSoldierBattleResp,10:SelectResp:>InteractSoldierSelectResp,11:EventSettlementOfDisputeBattleResp:>InteractEventSettlementOfDisputeBattleResp,12:CheckStageSettleResp:>InteractCheckStageSettleResp,13:DeploySyncResp:>InteractDeploySyncResp,14:StoryEventOfPersonalitySelectResp:>InteractStoryEventOfPersonalitySelectResp,15:Progress:r>SoldierBuffProgress,16:NilResp:>" +
    "Nil,17:StoryEventOfCostlySelectResp:>InteractStoryEventOfCostlySelectResp,2047:NextPackage:b\nSoldierLearnReq|1:Season:u,2:GroupId:u,3:StepId:i,2047:NextPackage:b\nSoldierPartnerTraceReq|1:PartnerType:u,2:Trace:u,2047:NextPackage:b\nSoldierSeasonRewardReceiveResp|1:Rewards:r>ItemTpl,2:Change:>ChangeInfo,3:CurRewardLv:u,2047:NextPackage:b\nStarTowerApplyReq|1:Id:u,2:FormationId:u,3:CharHp:u,4:MapId:u,5" +
    ":ParamId:u,6:MapParam:s,7:MapTableId:u,15:Sweep:u,2047:NextPackage:b\nStarTowerApplyResp|1:Info:>StarTowerInfo,2:LastId:u,4:CoinQty:u,5:Infos:r>SubNoteSkillInfo,6:FateCardId:u,7:NewFateCard:u,8:SweepTicket:u,9:SweepTicketUndated:u,15:Change:>ChangeInfo,2047:NextPackage:b\nStarTowerBookPotentialGetResp|1:Potentials:r>StarTowerBookPotential,2:ReceivedIds:ru,2047:NextPackage:b\nStarTowerBookEventRewardR" +
    "eceiveResp|1:Change:>ChangeInfo,2:ReceivedIds:ru,2047:NextPackage:b\nStarTowerBookPotentialBriefListResp|1:Infos:r>StarTowerBookCharPotentialBrief,2047:NextPackage:b\nStarTowerBookPotentialRewardReceiveResp|1:Change:>ChangeInfo,2:ReceivedIds:ru,2047:NextPackage:b\nStarTowerBuildBriefListGetResp|1:Briefs:r>StarTowerBuildBrief,2047:NextPackage:b\nStarTowerBuildDeleteReq|1:BuildIds:ru,2047:NextPackage:b\n" +
    "StarTowerBuildDeleteResp|1:Change:>ChangeInfo,2:Ticket:u,2047:NextPackage:b\nStarTowerBuildDetailGetReq|1:BuildId:u,2047:NextPackage:b\nStarTowerBuildDetailGetResp|1:Detail:>StarTowerBuildDetail,2047:NextPackage:b\nStarTowerBuildLockUnlockReq|1:BuildId:u,2:Lock:u,2047:NextPackage:b\nStarTowerBuildNameSetReq|1:BuildId:u,2:Name:s,2047:NextPackage:b\nStarTowerBuildNoteModifyReq|1:BuildId:u,2:NoteChange:>I" +
    "temTpls,2047:NextPackage:b\nStarTowerBuildNoteModifyResp|1:Change:>ChangeInfo,2:Info:>StarTowerBuildInfo,2047:NextPackage:b\nStarTowerBuildPotentialModifyReq|1:BuildId:u,2:PotentialChange:>ItemTpls,2047:NextPackage:b\nStarTowerBuildPotentialModifyResp|1:Change:>ChangeInfo,2:Info:>StarTowerBuildInfo,2047:NextPackage:b\nStarTowerBuildPreferenceSetReq|1:CheckInIds:ru,2:CheckOutIds:ru,2047:NextPackage:b\nS" +
    "tarTowerBuildWhetherSaveReq|1:Delete:u,2:Lock:u,3:Preference:u,4:BuildName:s,2047:NextPackage:b\nStarTowerBuildWhetherSaveResp|1:Change:>ChangeInfo,2:Ticket:u,2047:NextPackage:b\nStarTowerGiveUpResp|1:Change:>ChangeInfo,2:Build:>StarTowerBuildInfo,3:Reward:r>NPCAffinityLevelReward,4:NpcInteraction:u,5:TowerRewards:r>ItemTpl,12:Floor:u,13:PotentialCnt:u,14:TotalTime:u,15:TotalDamages:ru,2047:NextPack" +
    "age:b\nStarTowerInteractReq|1:Id:u,2:EnterReq:>InteractEnterReq,3:BattleEndReq:>InteractBattleEndReq,4:SelectReq:>InteractSelectReq,5:RecoveryHPReq:>InteractRecoveryHPReq,6:HawkerReq:>InteractHawkerReq,2047:NextPackage:b\nStarTowerInteractResp|1:Id:u,2:Cases:r>StarTowerRoomCase,3:Change:>ChangeInfo,4:Data:>TowerChangeData,7:EnterResp:>InteractEnterResp,8:BattleEndResp:>InteractBattleEndResp,9:Select" +
    "Resp:>InteractSelectResp,10:StrengthenMachineResp:>InteractStrengthenMachineResp,14:Settle:>SettleDataResp,15:NilResp:>Nil,2047:NextPackage:b\nStoryApplyReq|1:Idx:u,2:Build:>UseBuild,2047:NextPackage:b\nStorySetInfoResp|1:Chapters:r>StorySetChapter,2047:NextPackage:b\nStorySetChapter|1:ChapterId:u,2:SectionIndex:u,3:RewardedIds:ru,2047:NextPackage:b\nStorySetRewardReceiveReq|1:ChapterId:u,2:SectionId:" +
    "u,2047:NextPackage:b\nStorySettle|1:Idx:u,2:Major:r>StoryOptions,3:Personality:r>StoryOptions,2047:NextPackage:b\nStorySettleReq|1:List:r>StorySettle,14:Events:>Events,15:Evidences:ru,2047:NextPackage:b\nStoryOptions|1:Group:u,2:Choice:u,3:Factor:u,2047:NextPackage:b\nTalentBackgroundSetReq|1:GroupId:u,2:CharId:u,2047:NextPackage:b\nTalentGroupUnlockResp|1:Change:>ChangeInfo,2:Nodes:ru,2047:NextPackage" +
    ":b\nTalentNodeResetResp|1:ResetKeyNode:u,2:Change:>ChangeInfo,2047:NextPackage:b\nTalentResetReq|1:CharId:u,2:GroupId:u,2047:NextPackage:b\nTalentUnlockResp|1:Change:>ChangeInfo,2:TalentId:u,2047:NextPackage:b\nTowerBookFateCardDetailResp|1:Cards:ru,2:Quests:ru,2047:NextPackage:b\nTowerBookFateCardRewardReq|1:CardBundleId:u,2:QuestId:u,2047:NextPackage:b\nTowerGrowthDetailResp|1:Detail:ru,2047:NextPacka" +
    "ge:b\nTowerGrowthGroupNodeUnlockResp|1:Nodes:ru,2:ChangeInfo:>ChangeInfo,2047:NextPackage:b\nTowerVitaEnergyBuyResp|1:Change:>ChangeInfo,2:Energy:u,2047:NextPackage:b\nTowerVitaProjectListResp|1:Projects:r>TowerVitaProject,2:UseId:u,2047:NextPackage:b\nTowerVitaProjectNameUpdateRep|1:Id:u,2:Name:s,2047:NextPackage:b\nTowerVitaProjectSetRep|1:Id:u,2047:NextPackage:b\nTowerVitaProjectUpdateRep|1:Projects:" +
    ">TowerVitaProject,2047:NextPackage:b\nTraceHuntApplyReq|1:OwnerUID:u,2:BossID:u,3:Build:>UseBuild,4:BossCreateTime:l,5:Difficulty:u,2047:NextPackage:b\nTraceHuntBossRewardReceiveResp|1:Level:u,2:Exp:u,3:ChangeInfo:>ChangeInfo,2047:NextPackage:b\nTraceHuntInfo|1:ControlID:u,2:Level:u,3:Exp:u,4:BossID:u,5:TraceProgress:u,6:HuntProgress:u,7:BossCreateTime:l,8:SelfHuntTimes:u,9:Build:>UseBuild,10:BossCol" +
    "lections:r>TraceHuntBossCollection,11:TraceLog:r>TraceHuntLogEntry,12:HuntLog:r>TraceHuntLogEntry,2047:NextPackage:b\nTraceHuntRecommendation|1:OwnerUID:u,2:BossID:u,3:BossCreateTime:l,4:IsFriend:u,5:IsStar:u,6:Info:>Friend,2047:NextPackage:b\nTraceHuntRecommendResp|1:Recommendations:r>TraceHuntRecommendation,2047:NextPackage:b\nTraceHuntSettleReq|1:Score:u,2:Star:u,15:Events:>Events,2047:NextPackage" +
    ":b\nTraceHuntSettleResp|1:Level:u,2:Exp:u,3:ChangeInfo:>ChangeInfo,4:SelfHuntTimes:u,5:BossCreateTime:l,6:HuntLog:r>TraceHuntLogEntry,2047:NextPackage:b\nTraceHuntTraceResp|1:BossID:u,2:ChangeInfo:>ChangeInfo,3:TraceLog:r>TraceHuntLogEntry,2047:NextPackage:b\nTravelerDuelInfo|1:DuelLevel:u,2:DuelExp:u,3:WeeklyAwardTimes:u,4:Levels:r>TravelerDuelBossLevel,5:Challenge:>TravelerDuelChallengeInfo,6:Quest" +
    "s:>Quests,2047:NextPackage:b\nTravelerDuelLevelApplyReq|1:Id:u,2:BuildId:u,3:AffixIds:ru,2047:NextPackage:b\nTravelerDuelLevelSettleReq|1:Star:u,2:Time:u,15:Events:>Events,2047:NextPackage:b\nTravelerDuelLevelSettleResp|1:First:u,2:Change:>ChangeInfo,3:AwardItems:r>ItemTpl,4:FirstItems:r>ItemTpl,5:DuelLevel:u,6:DuelExp:u,7:DuelExpChange:i,8:Affinities:r>AffinityInfo,9:BaseScore:u,10:TimeScore:u,11:Fi" +
    "nalScore:u,12:MaxScore:u,13:UploadRemainTimes:u,14:SurpriseItems:r>ItemTpl,2047:NextPackage:b\nTravelerDuelQuestRewardReceiveReq|1:Id:u,2:Type:u,2047:NextPackage:b\nTravelerDuelQuestRewardReceiveResp|1:QuestRewards:r>ItemTpl,2:Change:>ChangeInfo,2047:NextPackage:b\nTravelerDuelRankInfo|1:LastRefreshTime:l,2:Self:>TravelerDuelRankData,3:Rank:r>TravelerDuelRankData,4:UploadRemainTimes:u,2047:NextPackag" +
    "e:b\nTravelerDuelRankChar|1:Id:u,2:Level:u,2047:NextPackage:b\nTravelerDuelRankData|1:Id:u,2:NickName:s,3:WorldClass:u,4:HeadIcon:u,5:Score:u,6:Rank:u,7:BuildScore:u,8:TitlePrefix:u,9:TitleSuffix:u,10:Chars:r>TravelerDuelRankChar,15:Honors:r>HonorInfo,2047:NextPackage:b\nVampireSurvivorApplyReq|1:Id:u,2:Builds:r>UseBuild,2047:NextPackage:b\nVampireSurvivorApplyResp|1:Events:r>VampireSurvivorEvent,2:Se" +
    "lect:>VampireSurvivorFateCardSelect,3:Reward:>VampireSurvivorLevelReward,2047:NextPackage:b\nVampireSurvivorAreaChangeReq|1:KillCount:ru,2:Time:u,6:ClientData:>VampireClientData,7:Events:>Events,2047:NextPackage:b\nVampireSurvivorRewardSelectReq|1:Index:u,2:ReRoll:u,2047:NextPackage:b\nVampireSurvivorRewardSelectResp|1:Resp:>Success,2:Pkg:>VampireSurvivorFateCardSelect,2047:NextPackage:b\nVampireSurvi" +
    "vorInfoResp|1:Id:u,2:Events:r>VampireSurvivorEvent,3:Reward:>VampireSurvivorLevelReward,4:Scenes:r>VampireSceneInfo,5:FateCardIds:ru,6:ClientData:>VampireClientData,2047:NextPackage:b\nVampireSceneInfo|1:SceneType:u,2:Build:>UseBuild,3:KillCount:ru,4:Time:u,2047:NextPackage:b\nVampireSurvivorQuestRewardReceiveReq|1:QuestType:u,2:QuestIds:ru,2047:NextPackage:b\nVampireSurvivorRewardChestReq|1:EventTyp" +
    "e:u,2:Number:u,2047:NextPackage:b\nVampireSurvivorRewardChestResp|1:ChestCards:r>CardInfo,2:ExtraCards:r>CardInfo,2047:NextPackage:b\nVampireSurvivorSettleReq|1:KillCount:ru,2:Time:u,3:Defeat:u,7:Events:>Events,2047:NextPackage:b\nVampireSurvivorSettleResp|1:Victory:>VictoryData,2:Defeat:>DefeatData,2047:NextPackage:b\nVampireSurvivorAreaInfo|1:KillCount:ru,2:KillScore:ru,3:BossTime:u,4:Score:u,2047:N" +
    "extPackage:b\nVampireTalentDetailResp|1:Nodes:b,3:ResetTime:l,9:ActiveCount:u,10:ObtainCount:u,2047:NextPackage:b\nWeekBossApplyReq|1:Id:u,2:Build:>UseBuild,2047:NextPackage:b\nWeekBossSettleReq|1:Result:u,2:Time:u,7:Events:>Events,2047:NextPackage:b\nWeekBossLevelSettleResp|1:First:u,2:Change:>ChangeInfo,3:AwardItems:r>ItemTpl,4:FirstItems:r>ItemTpl,2047:NextPackage:b";

static System.Collections.Generic.Dictionary<int, string> SS_NAMES =
    new System.Collections.Generic.Dictionary<int, string>();
static bool SS_MAP_LOADED = false;

static System.Collections.Generic.Dictionary<string, string> SS_SCHEMA = null;

// 惰性建立字段表，合并游戏与静态资源两组 schema
void SS_EnsureSchema()
{
    if (SS_SCHEMA != null) return;

    var d = new System.Collections.Generic.Dictionary<string, string>();

    string all = SS_SCHEMA_STR + "\n" + SS_SCHEMA_META;
    int n = all.Length;
    int p = 0;

    while (p < n)
    {
        int nl = all.IndexOf('\n', p);
        if (nl < 0) nl = n;

        if (nl > p)
        {
            int bar = all.IndexOf('|', p);
            if (bar >= p && bar < nl)
                d[all.Substring(p, bar - p)] = all.Substring(bar + 1, nl - bar - 1);
        }
        p = nl + 1;
    }
    SS_SCHEMA = d;
}

// 字符串转字符数组
char[] SS_Chars(string s)
{
    var a = new char[s.Length];
    int i = 0;
    foreach (char c in s) { a[i] = c; i++; }
    return a;
}

// 按字段号查字段名与子类型
void SS_SchemaField(string spec, int num, out string name, out string sub, out string code)
{
    name = null; sub = null; code = null;
    if (spec == null || spec.Length == 0) return;

    char[] sc = SS_Chars(spec);
    int total = sc.Length;

    int p = 0;
    while (p < total)
    {
        int comma = total;
        for (int i = p; i < total; i++) if (sc[i] == ',') { comma = i; break; }

        int colon = -1;
        for (int i = p; i < comma; i++) if (sc[i] == ':') { colon = i; break; }
        if (colon < 0) { p = comma + 1; continue; }

        int n = 0;
        bool ok = true;
        for (int i = p; i < colon; i++)
        {
            char c = sc[i];
            if (c < '0' || c > '9') { ok = false; break; }
            n = n * 10 + (c - '0');
        }
        if (ok && n == num)
        {
            int sep = comma;
            for (int i = colon + 1; i < comma; i++)
                if (sc[i] == '>' || sc[i] == ':') { sep = i; break; }

            name = spec.Substring(colon + 1, sep - colon - 1);

            if (sep < comma)
            {
                if (sc[sep] == ':')
                {
                    int a = sep + 1;
                    int k = a;
                    if (comma - a >= 2 && sc[a] == 'r') k = a + 1;

                    if (sc[k] == '>')
                    {
                        sub = spec.Substring(k + 1, comma - k - 1);
                        code = (k > a) ? "rm" : null;
                    }
                    else code = spec.Substring(a, comma - a);
                }
                else
                {
                    sub = spec.Substring(sep + 1, comma - sep - 1);
                }
            }
            return;
        }
        p = comma + 1;
    }
}

// 按字段号查字段名、子类型与类型码
void SS_SchemaField(string spec, int num, out string name, out string sub)
{
    string code;
    SS_SchemaField(spec, num, out name, out sub, out code);
}

// 取字符串指定位置的字符
char SS_ChAt(string s, int i)
{
    if (s == null || i < 0 || i >= s.Length) return '\0';
    return SS_Chars(s)[i];
}

// 取首个字符
char SS_Ch0(string s) { return SS_ChAt(s, 0); }

// 判断类型码是否为标量
bool SS_CodeIsScalar(string code)
{
    if (code == null || code.Length != 1) return false;
    char c = SS_Ch0(code);
    return c == 'i' || c == 'l' || c == 'u' || c == 'f' || c == 'd' || c == 's' || c == 'b';
}

// 判断类型码是否为 repeated
bool SS_CodeIsRepeated(string code)
{
    return code != null && code.Length >= 2 && SS_Ch0(code) == 'r';
}

// 取类型码的基础类型
char SS_CodeBase(string code)
{
    if (code == null || code.Length == 0) return '?';
    if (SS_Ch0(code) == 'r' && code.Length >= 2) return SS_ChAt(code, 1);
    return SS_Ch0(code);
}

// 解 packed 数组里的标量
int SS_PackedVals(byte[] d, int off, int len, char baseType,
                  System.Collections.Generic.List<ulong> vals, int max)
{
    int p = off, end = off + len, cnt = 0;
    while (p < end)
    {
        ulong v = 0;
        if (baseType == 'i' || baseType == 'l' || baseType == 'u')
        {
            int shift = 0;
            bool done = false;
            while (p < end && shift < 64)
            {
                byte b = d[p++];
                v |= ((ulong)(b & 0x7F)) << shift;
                if ((b & 0x80) == 0) { done = true; break; }
                shift += 7;
            }
            if (!done) return -1;
        }
        else if (baseType == 'f')
        {
            if (p + 4 > end) return -1;
            v = (ulong)(d[p] | (d[p + 1] << 8) | (d[p + 2] << 16) | (d[p + 3] << 24));
            p += 4;
        }
        else if (baseType == 'd')
        {
            if (p + 8 > end) return -1;
            ulong t = 0;
            for (int i = 7; i >= 0; i--) t = (t << 8) | d[p + i];
            v = t;
            p += 8;
        }
        else return -1;

        if (vals != null && cnt < max) vals.Add(v);
        cnt++;
    }
    return cnt;
}

// 解析十进制整数
bool SS_ParseInt(string s, out int v)
{
    v = 0;
    if (s == null || s.Length == 0) return false;
    bool neg = false;
    bool first = true;
    int n = 0;
    foreach (char c in s)
    {
        if (first)
        {
            first = false;
            if (c == '-') { neg = true; continue; }
            if (c == '+') continue;
        }
        if (c < '0' || c > '9') return false;
        v = v * 10 + (c - '0');
        n++;
    }
    if (n == 0) return false;
    if (neg) v = -v;
    return true;
}

// 整数转字符串
string SS_IntStr(int v)
{
    if (v == 0) return "0";
    bool neg = v < 0;
    long a = neg ? -(long)v : (long)v;
    var tmp = new char[12];
    int n = 0;
    while (a > 0) { tmp[n++] = (char)('0' + (int)(a % 10)); a /= 10; }
    var sb = new System.Text.StringBuilder(13);
    if (neg) sb.Append('-');
    for (int i = n - 1; i >= 0; i--) sb.Append(tmp[i]);
    return sb.ToString();
}

// 数字转字符
char SS_DigitChar(int d)
{
    if (d < 10) return (char)('0' + d);
    return (char)('A' + (d - 10));
}

// 半字节转十六进制字符
char SS_HexChar(int d)
{
    if (d < 10) return (char)('0' + d);
    return (char)('a' + (d - 10));
}

// 无符号整数按进制转字符串
string SS_UIntStr(ulong v, int radix)
{
    if (v == 0) return "0";
    var tmp = new char[24];
    int n = 0;
    while (v > 0) { tmp[n++] = SS_DigitChar((int)(v % (ulong)radix)); v /= (ulong)radix; }
    var sb = new System.Text.StringBuilder(24);
    for (int i = n - 1; i >= 0; i--) sb.Append(tmp[i]);
    return sb.ToString();
}

// 有符号长整数转字符串
string SS_LongStr(long v)
{
    bool neg = v < 0;
    ulong a = neg ? (ulong)(-v) : (ulong)v;
    return (neg ? "-" : "") + SS_UIntStr(a, 10);
}

// 惰性解析 msgId 名称表
void SS_EnsureMap()
{
    if (SS_MAP_LOADED) return;
    SS_MAP_LOADED = true;

    string txt = SS_MAP_STR;
    int p = 0;
    while (p < txt.Length)
    {
        int bar = txt.IndexOf('|', p);
        if (bar < 0) bar = txt.Length;
        int c = txt.IndexOf(':', p);
        if (c > p && c < bar)
        {
            int id;
            if (SS_ParseInt(txt.Substring(p, c - p), out id))
            {
                string nm = txt.Substring(c + 1, bar - c - 1);
                if (!SS_NAMES.ContainsKey(id)) SS_NAMES[id] = nm;
            }
        }
        p = bar + 1;
    }
}

// 按 msgId 取消息名
string SS_MsgName(int id)
{
    SS_EnsureMap();
    string nm;
    if (SS_NAMES.TryGetValue(id, out nm)) return nm;
    return "0x" + SS_UIntStr((ulong)(uint)id, 16);
}

// 十六进制字符转数值
int SS_HexVal(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

// 十六进制字符串转字节
byte[] SS_Hex(string s)
{
    if (s == null) return new byte[0];
    var clean = new System.Text.StringBuilder(s.Length);
    foreach (char c in s)
    {
        if (c == ' ' || c == '-' || c == '\t' || c == '\r' || c == '\n') continue;
        clean.Append(c);
    }
    string t = clean.ToString();
    if (t.Length == 0 || (t.Length & 1) != 0) return new byte[0];

    var r = new byte[t.Length / 2];
    int rp = 0;
    int hi = -1;
    foreach (char c in t)
    {
        int v = SS_HexVal(c);
        if (v < 0) return new byte[0];
        if (hi < 0) hi = v;
        else { r[rp++] = (byte)((hi << 4) | v); hi = -1; }
    }
    return r;
}

// 字节转十六进制字符串
string SS_HexStr(byte[] b)
{
    if (b == null) return "";
    var sb = new System.Text.StringBuilder(b.Length * 2);
    for (int i = 0; i < b.Length; i++)
    {
        sb.Append(SS_HexChar(b[i] >> 4));
        sb.Append(SS_HexChar(b[i] & 15));
    }
    return sb.ToString();
}

// ASCII 字符串转字节
byte[] SS_AsciiBytes(string s)
{
    var r = new byte[s.Length];
    int n = 0;
    foreach (char c in s) r[n++] = (byte)(c & 0xFF);
    return r;
}

// 校验字节串是否为合法 UTF-8
bool SS_Utf8Valid(byte[] b, int off, int len)
{
    int i = off, end = off + len;
    while (i < end)
    {
        byte c = b[i];
        int n;
        if (c < 0x80) n = 1;
        else if ((c & 0xE0) == 0xC0) n = 2;
        else if ((c & 0xF0) == 0xE0) n = 3;
        else if ((c & 0xF8) == 0xF0) n = 4;
        else return false;
        if (i + n > end) return false;
        for (int k = 1; k < n; k++) if ((b[i + k] & 0xC0) != 0x80) return false;
        i += n;
    }
    return true;
}

// UTF-8 字节转字符串
string SS_Utf8String(byte[] b)
{
    if (b == null) return "";
    var sb = new System.Text.StringBuilder(b.Length);
    int i = 0, n = b.Length;
    while (i < n)
    {
        byte c = b[i];
        if (c < 0x80) { sb.Append((char)c); i++; continue; }

        int cp;
        if ((c & 0xE0) == 0xC0 && i + 1 < n)
        {
            cp = ((c & 0x1F) << 6) | (b[i + 1] & 0x3F);
            i += 2;
        }
        else if ((c & 0xF0) == 0xE0 && i + 2 < n)
        {
            cp = ((c & 0x0F) << 12) | ((b[i + 1] & 0x3F) << 6) | (b[i + 2] & 0x3F);
            i += 3;
        }
        else if ((c & 0xF8) == 0xF0 && i + 3 < n)
        {
            cp = ((c & 0x07) << 18) | ((b[i + 1] & 0x3F) << 12)
               | ((b[i + 2] & 0x3F) << 6) | (b[i + 3] & 0x3F);
            i += 4;
        }
        else { sb.Append('?'); i++; continue; }

        if (cp < 0x10000) sb.Append((char)cp);
        else
        {
            cp -= 0x10000;
            sb.Append((char)(0xD800 + (cp >> 10)));
            sb.Append((char)(0xDC00 + (cp & 0x3FF)));
        }
    }
    return sb.ToString();
}

// 循环左移一位
byte SS_Rol1(byte b) { return (byte)(((b << 1) | (b >> 7)) & 0xFF); }

// 循环右移一位
byte SS_Ror1(byte b) { return (byte)(((b >> 1) | ((b & 1) << 7)) & 0xFF); }

// 读大端 2 字节整数
int SS_BE16(byte[] b, int o) { return (b[o] << 8) | b[o + 1]; }

// 读大端 8 字节整数
long SS_BE64(byte[] b, int o)
{
    long v = 0;
    for (int i = 0; i < 8; i++) v = (v << 8) | b[o + i];
    return v;
}

// 读小端 4 字节整数
uint SS_Le32(byte[] b, int o) { return (uint)(b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)); }

// 读大端 4 字节整数
uint SS_Be32(byte[] b, int o) { return ((uint)b[o] << 24) | ((uint)b[o + 1] << 16) | ((uint)b[o + 2] << 8) | b[o + 3]; }

// 写大端 4 字节整数
void SS_PutBe32(byte[] b, int o, uint v) { b[o] = (byte)(v >> 24); b[o + 1] = (byte)(v >> 16); b[o + 2] = (byte)(v >> 8); b[o + 3] = (byte)v; }

// 写小端 4 字节整数
void SS_PutLe32(byte[] b, int o, uint v) { b[o] = (byte)v; b[o + 1] = (byte)(v >> 8); b[o + 2] = (byte)(v >> 16); b[o + 3] = (byte)(v >> 24); }

// 32 位循环右移
uint SS_Ror32(uint x, int n) { return (x >> n) | (x << (32 - n)); }

// 32 位循环左移
uint SS_Rol32(uint x, int n) { return (x << n) | (x >> (32 - n)); }

// 截取子字节
byte[] SS_Slice(byte[] src, int off, int len) { byte[] r = new byte[len]; for (int i = 0; i < len; i++) r[i] = src[off + i]; return r; }

// 判断是否全零
bool SS_AllZero(byte[] a) { for (int i = 0; i < a.Length; i++) if (a[i] != 0) return false; return true; }

// 比较两段字节是否一致
bool SS_SameBytes(byte[] a, byte[] b)
{
    if (a == null || b == null || a.Length != b.Length) return false;
    for (int i = 0; i < a.Length; i++) if (a[i] != b[i]) return false;
    return true;
}

// 生成重复字节
byte[] SS_Repeat(byte b, int n) { byte[] r = new byte[n]; for (int i = 0; i < n; i++) r[i] = b; return r; }

// 拆 chunked 分帧，返回载荷与各段位置
bool SS_TryDechunk(byte[] wire, out byte[] payload, out int[] segOff, out int[] segLen)
{
    payload = null; segOff = null; segLen = null;
    if (wire == null || wire.Length < 8) return false;

    var offs = new System.Collections.Generic.List<int>();
    var lens = new System.Collections.Generic.List<int>();
    int total = 0;
    bool done = false;
    int p = 0;

    while (p < wire.Length)
    {
        int lineEnd = -1;
        int lim = p + 32; if (lim > wire.Length) lim = wire.Length;
        for (int i = p; i < lim; i++)
        {
            byte c = wire[i];
            if (c == 0x0A) { lineEnd = i; break; }
            if (c == 0x0D || c == ';') continue;
            if (SS_HexVal((char)(c & 0xFF)) < 0) return false;
        }
        if (lineEnd < 0) return false;

        ulong sz = 0;
        bool any = false;
        for (int q = p; q < lineEnd; q++)
        {
            byte c = wire[q];
            if (c == 0x0D || c == ';') break;
            int d = SS_HexVal((char)(c & 0xFF));
            if (d < 0) break;
            sz = (sz << 4) + (ulong)(uint)d;
            any = true;
            if (sz > 0x4000000UL) return false;
        }
        if (!any) return false;

        int ds = lineEnd + 1;
        if (sz == 0) { done = true; break; }

        int de = ds + (int)sz;
        if (de >= wire.Length) return false;

        offs.Add(ds);
        lens.Add((int)sz);
        total += (int)sz;

        p = de;
        if (p < wire.Length && wire[p] == 0x0D) p++;
        if (p < wire.Length && wire[p] == 0x0A) p++;
    }

    if (!done || offs.Count == 0 || total < 8) return false;

    byte[] buf = new byte[total];
    int at = 0;
    for (int i = 0; i < offs.Count; i++)
    {
        int o = offs[i];
        for (int j = 0; j < lens[i]; j++) buf[at++] = wire[o + j];
    }

    payload = buf;

    segOff = new int[offs.Count];
    segLen = new int[lens.Count];
    for (int i = 0; i < offs.Count; i++) { segOff[i] = offs[i]; segLen[i] = lens[i]; }
    return true;
}

// 按原分帧布局把新载荷写回 chunked
byte[] SS_Rechunk(byte[] tpl, byte[] payload, int[] segOff, int[] segLen)
{
    if (tpl == null || payload == null || segOff == null || segLen == null) return null;

    int total = 0;
    for (int i = 0; i < segLen.Length; i++) total += segLen[i];
    if (total != payload.Length) return null;

    byte[] r = SS_Slice(tpl, 0, tpl.Length);
    int src = 0;
    for (int i = 0; i < segOff.Length; i++)
    {
        int o = segOff[i];
        for (int j = 0; j < segLen[i]; j++) r[o + j] = payload[src + j];
        src += segLen[i];
    }
    return r;
}

static uint[] SS_SHA_K = new uint[] {
    0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u,
    0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,
    0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
    0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,0x06ca6351u,0x14292967u,
    0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,
    0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
    0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u,
    0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u
};

// SHA-256 摘要
byte[] SS_Sha256(byte[] d)
{
    int len = d.Length;
    int total = ((len + 9 + 63) / 64) * 64;
    byte[] m = new byte[total];
    for (int i = 0; i < len; i++) m[i] = d[i];
    m[len] = 0x80;
    ulong bits = (ulong)len * 8;
    for (int i = 0; i < 8; i++) m[total - 1 - i] = (byte)(bits >> (8 * i));

    uint h0 = 0x6a09e667u, h1 = 0xbb67ae85u, h2 = 0x3c6ef372u, h3 = 0xa54ff53au;
    uint h4 = 0x510e527fu, h5 = 0x9b05688cu, h6 = 0x1f83d9abu, h7 = 0x5be0cd19u;

    uint[] w = new uint[64];
    for (int off = 0; off < total; off += 64)
    {
        for (int i = 0; i < 16; i++) w[i] = SS_Be32(m, off + i * 4);
        for (int i = 16; i < 64; i++)
        {
            uint s0 = SS_Ror32(w[i - 15], 7) ^ SS_Ror32(w[i - 15], 18) ^ (w[i - 15] >> 3);
            uint s1 = SS_Ror32(w[i - 2], 17) ^ SS_Ror32(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }
        uint a = h0, b = h1, c = h2, dd = h3, e = h4, f = h5, g = h6, h = h7;
        for (int i = 0; i < 64; i++)
        {
            uint S1 = SS_Ror32(e, 6) ^ SS_Ror32(e, 11) ^ SS_Ror32(e, 25);
            uint ch = (e & f) ^ ((~e) & g);
            uint t1 = h + S1 + ch + SS_SHA_K[i] + w[i];
            uint S0 = SS_Ror32(a, 2) ^ SS_Ror32(a, 13) ^ SS_Ror32(a, 22);
            uint mj = (a & b) ^ (a & c) ^ (b & c);
            uint t2 = S0 + mj;
            h = g; g = f; f = e; e = dd + t1; dd = c; c = b; b = a; a = t1 + t2;
        }
        h0 += a; h1 += b; h2 += c; h3 += dd; h4 += e; h5 += f; h6 += g; h7 += h;
    }
    byte[] o = new byte[32];
    uint[] H = new uint[] { h0, h1, h2, h3, h4, h5, h6, h7 };
    for (int i = 0; i < 8; i++) SS_PutBe32(o, i * 4, H[i]);
    return o;
}

// HMAC-SHA256
byte[] SS_Hmac256(byte[] key, byte[] data)
{
    byte[] k = new byte[64];
    if (key.Length > 64)
    {
        byte[] kk = SS_Sha256(key);
        for (int i = 0; i < 32; i++) k[i] = kk[i];
    }
    else
    {
        for (int i = 0; i < key.Length; i++) k[i] = key[i];
    }

    byte[] inner = new byte[64 + data.Length];
    for (int i = 0; i < 64; i++) inner[i] = (byte)(k[i] ^ 0x36);
    for (int i = 0; i < data.Length; i++) inner[64 + i] = data[i];
    byte[] mid = SS_Sha256(inner);

    byte[] outer = new byte[64 + 32];
    for (int i = 0; i < 64; i++) outer[i] = (byte)(k[i] ^ 0x5c);
    for (int i = 0; i < 32; i++) outer[64 + i] = mid[i];
    return SS_Sha256(outer);
}

// HKDF-SHA256 派生 32 字节
byte[] SS_Hkdf32(byte[] ikm, byte[] salt, byte[] info)
{
    byte[] prk = SS_Hmac256(salt, ikm);
    byte[] t = new byte[info.Length + 1];
    for (int i = 0; i < info.Length; i++) t[i] = info[i];
    t[info.Length] = 0x01;
    return SS_Hmac256(prk, t);
}

static byte[] SS_SBOX = new byte[] {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

// GF(2^8) 乘 2
byte SS_AesMul2(byte b) { return (byte)(((b << 1) ^ (((b >> 7) & 1) * 0x1b)) & 0xFF); }

// GF(2^8) 乘 3
byte SS_AesMul3(byte b) { return (byte)(SS_AesMul2(b) ^ b); }

// 用 S 盒替换单个字节
byte SS_AesSubWord0(uint w) { return SS_SBOX[w >> 24]; }

// AES 密钥扩展用的 SubWord
uint SS_AesSubWord(uint w)
{
    return ((uint)SS_SBOX[w >> 24] << 24) | ((uint)SS_SBOX[(w >> 16) & 0xFF] << 16)
         | ((uint)SS_SBOX[(w >> 8) & 0xFF] << 8) | SS_SBOX[w & 0xFF];
}

// 轮密钥字循环移位
uint SS_AesRotWord(uint w) { return (w << 8) | (w >> 24); }

// 展开 AES 轮密钥
int SS_AesExpand(byte[] key, out uint[] rk)
{
    int nk = key.Length / 4;
    int nr = nk + 6;
    int total = 4 * (nr + 1);
    rk = new uint[total];
    for (int i = 0; i < nk; i++) rk[i] = SS_Be32(key, i * 4);

    byte rcon = 1;
    for (int i = nk; i < total; i++)
    {
        uint t = rk[i - 1];
        if (i % nk == 0)
        {
            t = SS_AesSubWord(SS_AesRotWord(t)) ^ ((uint)rcon << 24);
            rcon = SS_AesMul2(rcon);
        }
        else if (nk > 6 && (i % nk) == 4)
        {
            t = SS_AesSubWord(t);
        }
        rk[i] = rk[i - nk] ^ t;
    }
    return nr;
}

// 轮密钥异或
void SS_AesAddKey(uint[] rk, int off, byte[] s)
{
    for (int c = 0; c < 4; c++)
    {
        uint w = rk[off + c];
        s[c * 4] ^= (byte)(w >> 24);
        s[c * 4 + 1] ^= (byte)(w >> 16);
        s[c * 4 + 2] ^= (byte)(w >> 8);
        s[c * 4 + 3] ^= (byte)w;
    }
}

// AES 字节替换与行移位
void SS_AesSubShift(byte[] s)
{
    byte[] t = new byte[16];
    for (int c = 0; c < 4; c++)
        for (int r = 0; r < 4; r++)
            t[c * 4 + r] = SS_SBOX[s[((c + r) & 3) * 4 + r]];
    for (int i = 0; i < 16; i++) s[i] = t[i];
}

// AES 列混合
void SS_AesMixCols(byte[] s)
{
    for (int c = 0; c < 4; c++)
    {
        int i = c * 4;
        byte a0 = s[i], a1 = s[i + 1], a2 = s[i + 2], a3 = s[i + 3];
        s[i] = (byte)(SS_AesMul2(a0) ^ SS_AesMul3(a1) ^ a2 ^ a3);
        s[i + 1] = (byte)(a0 ^ SS_AesMul2(a1) ^ SS_AesMul3(a2) ^ a3);
        s[i + 2] = (byte)(a0 ^ a1 ^ SS_AesMul2(a2) ^ SS_AesMul3(a3));
        s[i + 3] = (byte)(SS_AesMul3(a0) ^ a1 ^ a2 ^ SS_AesMul2(a3));
    }
}

// AES 加密一个分组
void SS_AesEncBlock(uint[] rk, int nr, byte[] s)
{
    SS_AesAddKey(rk, 0, s);
    for (int r = 1; r < nr; r++)
    {
        SS_AesSubShift(s);
        SS_AesMixCols(s);
        SS_AesAddKey(rk, r * 4, s);
    }
    SS_AesSubShift(s);
    SS_AesAddKey(rk, nr * 4, s);
}

// GF(2^128) 乘法
void SS_GMul(ref ulong a0, ref ulong a1, ulong h0, ulong h1)
{
    ulong z0 = 0, z1 = 0;
    ulong v0 = h0, v1 = h1;
    for (int i = 0; i < 128; i++)
    {
        ulong bit = (i < 64) ? ((a0 >> (63 - i)) & 1UL) : ((a1 >> (127 - i)) & 1UL);
        if (bit != 0) { z0 ^= v0; z1 ^= v1; }
        ulong lsb = v1 & 1UL;
        v1 = (v1 >> 1) | (v0 << 63);
        v0 = v0 >> 1;
        if (lsb != 0) v0 ^= 0xE100000000000000UL;
    }
    a0 = z0; a1 = z1;
}

// GHASH 处理一个分组
void SS_GHashBlock(ref ulong y0, ref ulong y1, byte[] d, int off, int len, ulong h0, ulong h1)
{
    ulong x0 = 0, x1 = 0;
    for (int i = 0; i < 16; i++)
    {
        byte b = (off + i < len) ? d[off + i] : (byte)0;
        if (i < 8) x0 = (x0 << 8) | b; else x1 = (x1 << 8) | b;
    }
    y0 ^= x0; y1 ^= x1;
    SS_GMul(ref y0, ref y1, h0, h1);
}

// AES-GCM 解密并校验 tag
byte[] SS_GcmDec(byte[] key, byte[] nonce, byte[] ct, byte[] tag, byte[] aad)
{
    if (key.Length != 16 && key.Length != 32) return null;

    uint[] rk;
    int nr = SS_AesExpand(key, out rk);

    byte[] hb = new byte[16];
    SS_AesEncBlock(rk, nr, hb);
    ulong h0 = 0, h1 = 0;
    for (int i = 0; i < 8; i++) h0 = (h0 << 8) | hb[i];
    for (int i = 8; i < 16; i++) h1 = (h1 << 8) | hb[i];

    byte[] j0 = new byte[16];
    for (int i = 0; i < 12; i++) j0[i] = nonce[i];
    j0[15] = 1;

    byte[] pt = new byte[ct.Length];
    byte[] ctr = new byte[16];
    for (int i = 0; i < 16; i++) ctr[i] = j0[i];
    for (int off = 0; off < ct.Length; off += 16)
    {
        for (int i = 15; i >= 12; i--) { ctr[i] = (byte)(ctr[i] + 1); if (ctr[i] != 0) break; }
        byte[] ks = new byte[16];
        for (int i = 0; i < 16; i++) ks[i] = ctr[i];
        SS_AesEncBlock(rk, nr, ks);
        int n = ct.Length - off; if (n > 16) n = 16;
        for (int i = 0; i < n; i++) pt[off + i] = (byte)(ct[off + i] ^ ks[i]);
    }

    ulong y0 = 0, y1 = 0;
    for (int off = 0; off < aad.Length; off += 16) SS_GHashBlock(ref y0, ref y1, aad, off, aad.Length, h0, h1);
    for (int off = 0; off < ct.Length; off += 16) SS_GHashBlock(ref y0, ref y1, ct, off, ct.Length, h0, h1);
    y0 ^= (ulong)aad.Length * 8;
    y1 ^= (ulong)ct.Length * 8;
    SS_GMul(ref y0, ref y1, h0, h1);

    byte[] ej = new byte[16];
    for (int i = 0; i < 16; i++) ej[i] = j0[i];
    SS_AesEncBlock(rk, nr, ej);

    byte[] calc = new byte[16];
    for (int i = 0; i < 8; i++) calc[i] = (byte)(ej[i] ^ (byte)(y0 >> (8 * (7 - i))));
    for (int i = 0; i < 8; i++) calc[8 + i] = (byte)(ej[8 + i] ^ (byte)(y1 >> (8 * (7 - i))));
    for (int i = 0; i < 16; i++) if (calc[i] != tag[i]) return null;

    return pt;
}

static byte[] SS_INVSBOX = null;

// 初始化 AES 逆 S 盒
void SS_AesInvInit()
{
    if (SS_INVSBOX != null) return;
    var inv = new byte[256];
    for (int i = 0; i < 256; i++) inv[SS_SBOX[i]] = (byte)i;
    SS_INVSBOX = inv;
}

// GF(2^8) 乘法
byte SS_AesMul(byte a, byte b)
{
    byte r = 0;
    for (int i = 0; i < 8; i++)
    {
        if ((b & 1) != 0) r ^= a;
        bool hi = (a & 0x80) != 0;
        a = (byte)(a << 1);
        if (hi) a ^= 0x1b;
        b = (byte)(b >> 1);
    }
    return r;
}

// AES 逆行移位与逆字节替换
void SS_AesInvSubShift(byte[] s)
{
    var t = new byte[16];
    for (int c = 0; c < 4; c++)
        for (int r = 0; r < 4; r++)
            t[c * 4 + r] = SS_INVSBOX[s[((c - r + 4) & 3) * 4 + r]];
    for (int i = 0; i < 16; i++) s[i] = t[i];
}

// AES 逆列混合
void SS_AesInvMixCols(byte[] s)
{
    for (int c = 0; c < 4; c++)
    {
        int i = c * 4;
        byte a0 = s[i], a1 = s[i + 1], a2 = s[i + 2], a3 = s[i + 3];
        s[i]     = (byte)(SS_AesMul(a0, 14) ^ SS_AesMul(a1, 11) ^ SS_AesMul(a2, 13) ^ SS_AesMul(a3, 9));
        s[i + 1] = (byte)(SS_AesMul(a0, 9)  ^ SS_AesMul(a1, 14) ^ SS_AesMul(a2, 11) ^ SS_AesMul(a3, 13));
        s[i + 2] = (byte)(SS_AesMul(a0, 13) ^ SS_AesMul(a1, 9)  ^ SS_AesMul(a2, 14) ^ SS_AesMul(a3, 11));
        s[i + 3] = (byte)(SS_AesMul(a0, 11) ^ SS_AesMul(a1, 13) ^ SS_AesMul(a2, 9)  ^ SS_AesMul(a3, 14));
    }
}

// AES 解密一个分组
void SS_AesDecBlock(uint[] rk, int nr, byte[] s)
{
    SS_AesAddKey(rk, nr * 4, s);
    for (int r = nr - 1; r >= 1; r--)
    {
        SS_AesInvSubShift(s);
        SS_AesAddKey(rk, r * 4, s);
        SS_AesInvMixCols(s);
    }
    SS_AesInvSubShift(s);
    SS_AesAddKey(rk, 0, s);
}

// AES-128-CBC 解密并去填充
byte[] SS_AesCbcDec(byte[] key, byte[] iv, byte[] ct)
{
    if (key == null || (key.Length != 16 && key.Length != 24 && key.Length != 32)) return null;
    if (iv == null || iv.Length != 16 || ct == null || ct.Length == 0) return null;
    if ((ct.Length & 15) != 0) return null;

    SS_AesInvInit();

    uint[] rk;
    int nr = SS_AesExpand(key, out rk);

    int blocks = ct.Length >> 4;
    var outb = new byte[ct.Length];
    var prev = new byte[16];
    var blk = new byte[16];
    for (int i = 0; i < 16; i++) prev[i] = iv[i];

    for (int b = 0; b < blocks; b++)
    {
        int o = b << 4;
        for (int i = 0; i < 16; i++) blk[i] = ct[o + i];
        SS_AesDecBlock(rk, nr, blk);
        for (int i = 0; i < 16; i++)
        {
            outb[o + i] = (byte)(blk[i] ^ prev[i]);
            prev[i] = ct[o + i];
        }
    }

    int n = outb.Length;
    int pad = outb[n - 1];
    bool stripped = false;
    if (pad >= 1 && pad <= 16 && pad <= n)
    {
        bool ok = true;
        for (int i = n - pad; i < n; i++) if (outb[i] != pad) { ok = false; break; }
        if (ok) { n -= pad; stripped = true; }
    }
    if (!stripped)
    {
        while (n > 0 && outb[n - 1] == 0) n--;
    }
    if (n == outb.Length) return outb;

    var res = new byte[n];
    for (int i = 0; i < n; i++) res[i] = outb[i];
    return res;
}

// ChaCha20 四分之一轮
void SS_ChaQr(uint[] x, int a, int b, int c, int d)
{
    x[a] += x[b]; x[d] ^= x[a]; x[d] = SS_Rol32(x[d], 16);
    x[c] += x[d]; x[b] ^= x[c]; x[b] = SS_Rol32(x[b], 12);
    x[a] += x[b]; x[d] ^= x[a]; x[d] = SS_Rol32(x[d], 8);
    x[c] += x[d]; x[b] ^= x[c]; x[b] = SS_Rol32(x[b], 7);
}

// ChaCha20 生成一个密钥块
void SS_ChaBlock(uint[] st, byte[] outb, int off)
{
    uint[] x = new uint[16];
    for (int i = 0; i < 16; i++) x[i] = st[i];
    for (int i = 0; i < 10; i++)
    {
        SS_ChaQr(x, 0, 4, 8, 12); SS_ChaQr(x, 1, 5, 9, 13); SS_ChaQr(x, 2, 6, 10, 14); SS_ChaQr(x, 3, 7, 11, 15);
        SS_ChaQr(x, 0, 5, 10, 15); SS_ChaQr(x, 1, 6, 11, 12); SS_ChaQr(x, 2, 7, 8, 13); SS_ChaQr(x, 3, 4, 9, 14);
    }
    for (int i = 0; i < 16; i++) SS_PutLe32(outb, off + i * 4, x[i] + st[i]);
}

// Poly1305 认证码
byte[] SS_Poly1305(byte[] key, byte[] msg)
{
    uint t0 = SS_Le32(key, 0), t1 = SS_Le32(key, 4), t2 = SS_Le32(key, 8), t3 = SS_Le32(key, 12);
    uint r0 = t0 & 0x3ffffffu;
    uint r1 = ((t0 >> 26) | (t1 << 6)) & 0x3ffff03u;
    uint r2 = ((t1 >> 20) | (t2 << 12)) & 0x3ffc0ffu;
    uint r3 = ((t2 >> 14) | (t3 << 18)) & 0x3f03fffu;
    uint r4 = (t3 >> 8) & 0x00fffffu;
    uint s1 = r1 * 5, s2 = r2 * 5, s3 = r3 * 5, s4 = r4 * 5;

    uint h0 = 0, h1 = 0, h2 = 0, h3 = 0, h4 = 0;
    int nblocks = (msg.Length + 15) / 16;

    for (int bi = 0; bi < nblocks; bi++)
    {
        byte[] blk = new byte[16];
        int start = bi * 16;
        int rem = msg.Length - start;
        bool isFinal = rem < 16;
        if (!isFinal) { for (int i = 0; i < 16; i++) blk[i] = msg[start + i]; }
        else { for (int i = 0; i < rem; i++) blk[i] = msg[start + i]; blk[rem] = 1; }

        uint b0 = SS_Le32(blk, 0), b1 = SS_Le32(blk, 4), b2 = SS_Le32(blk, 8), b3 = SS_Le32(blk, 12);
        h0 += b0 & 0x3ffffffu;
        h1 += ((b0 >> 26) | (b1 << 6)) & 0x3ffffffu;
        h2 += ((b1 >> 20) | (b2 << 12)) & 0x3ffffffu;
        h3 += ((b2 >> 14) | (b3 << 18)) & 0x3ffffffu;
        h4 += (b3 >> 8) | (isFinal ? 0u : (1u << 24));

        ulong d0 = (ulong)h0 * r0 + (ulong)h1 * s4 + (ulong)h2 * s3 + (ulong)h3 * s2 + (ulong)h4 * s1;
        ulong d1 = (ulong)h0 * r1 + (ulong)h1 * r0 + (ulong)h2 * s4 + (ulong)h3 * s3 + (ulong)h4 * s2;
        ulong d2 = (ulong)h0 * r2 + (ulong)h1 * r1 + (ulong)h2 * r0 + (ulong)h3 * s4 + (ulong)h4 * s3;
        ulong d3 = (ulong)h0 * r3 + (ulong)h1 * r2 + (ulong)h2 * r1 + (ulong)h3 * r0 + (ulong)h4 * s4;
        ulong d4 = (ulong)h0 * r4 + (ulong)h1 * r3 + (ulong)h2 * r2 + (ulong)h3 * r1 + (ulong)h4 * r0;

        ulong c;
        c = d0 >> 26; h0 = (uint)d0 & 0x3ffffffu;
        d1 += c; c = d1 >> 26; h1 = (uint)d1 & 0x3ffffffu;
        d2 += c; c = d2 >> 26; h2 = (uint)d2 & 0x3ffffffu;
        d3 += c; c = d3 >> 26; h3 = (uint)d3 & 0x3ffffffu;
        d4 += c; c = d4 >> 26; h4 = (uint)d4 & 0x3ffffffu;
        h0 += (uint)c * 5; c = h0 >> 26; h0 &= 0x3ffffffu;
        h1 += (uint)c;
    }

    uint cc;
    cc = h1 >> 26; h1 &= 0x3ffffffu;
    h2 += cc; cc = h2 >> 26; h2 &= 0x3ffffffu;
    h3 += cc; cc = h3 >> 26; h3 &= 0x3ffffffu;
    h4 += cc; cc = h4 >> 26; h4 &= 0x3ffffffu;
    h0 += cc * 5; cc = h0 >> 26; h0 &= 0x3ffffffu;
    h1 += cc;

    uint g0 = h0 + 5; cc = g0 >> 26; g0 &= 0x3ffffffu;
    uint g1 = h1 + cc; cc = g1 >> 26; g1 &= 0x3ffffffu;
    uint g2 = h2 + cc; cc = g2 >> 26; g2 &= 0x3ffffffu;
    uint g3 = h3 + cc; cc = g3 >> 26; g3 &= 0x3ffffffu;
    uint g4 = h4 + cc - (1u << 26);

    if ((g4 >> 31) == 0) { h0 = g0; h1 = g1; h2 = g2; h3 = g3; h4 = g4; }

    uint w0 = h0 | (h1 << 26);
    uint w1 = (h1 >> 6) | (h2 << 20);
    uint w2 = (h2 >> 12) | (h3 << 14);
    uint w3 = (h3 >> 18) | (h4 << 8);

    uint p0 = SS_Le32(key, 16), p1 = SS_Le32(key, 20), p2 = SS_Le32(key, 24), p3 = SS_Le32(key, 28);

    byte[] o = new byte[16];
    ulong f = (ulong)w0 + p0; SS_PutLe32(o, 0, (uint)f);
    f = (ulong)w1 + p1 + (f >> 32); SS_PutLe32(o, 4, (uint)f);
    f = (ulong)w2 + p2 + (f >> 32); SS_PutLe32(o, 8, (uint)f);
    f = (ulong)w3 + p3 + (f >> 32); SS_PutLe32(o, 12, (uint)f);
    return o;
}

// ChaCha20-Poly1305 解密并校验 tag
byte[] SS_ChachaDec(byte[] key, byte[] nonce, byte[] ct, byte[] tag, byte[] aad)
{
    if (key.Length != 32) return null;

    uint[] st = new uint[16];
    st[0] = 0x61707865u; st[1] = 0x3320646eu; st[2] = 0x79622d32u; st[3] = 0x6b206574u;
    for (int i = 0; i < 8; i++) st[4 + i] = SS_Le32(key, i * 4);
    st[12] = 0;
    st[13] = SS_Le32(nonce, 0); st[14] = SS_Le32(nonce, 4); st[15] = SS_Le32(nonce, 8);

    byte[] polyKey64 = new byte[64];
    SS_ChaBlock(st, polyKey64, 0);
    byte[] polyKey = new byte[32];
    for (int i = 0; i < 32; i++) polyKey[i] = polyKey64[i];

    int aadPad = (aad.Length % 16 == 0) ? 0 : 16 - (aad.Length % 16);
    int ctPad = (ct.Length % 16 == 0) ? 0 : 16 - (ct.Length % 16);
    byte[] mac = new byte[aad.Length + aadPad + ct.Length + ctPad + 16];
    int p = 0;
    for (int i = 0; i < aad.Length; i++) mac[p++] = aad[i];
    p += aadPad;
    for (int i = 0; i < ct.Length; i++) mac[p++] = ct[i];
    p += ctPad;
    ulong al = (ulong)aad.Length, cl = (ulong)ct.Length;
    for (int i = 0; i < 8; i++) { mac[p + i] = (byte)(al >> (8 * i)); mac[p + 8 + i] = (byte)(cl >> (8 * i)); }

    byte[] calc = SS_Poly1305(polyKey, mac);
    for (int i = 0; i < 16; i++) if (calc[i] != tag[i]) return null;

    byte[] pt = new byte[ct.Length];
    byte[] ks = new byte[64];
    uint counter = 1;
    for (int off = 0; off < ct.Length; off += 64)
    {
        st[12] = counter++;
        SS_ChaBlock(st, ks, 0);
        int n = ct.Length - off; if (n > 64) n = 64;
        for (int i = 0; i < n; i++) pt[off + i] = (byte)(ct[off + i] ^ ks[i]);
    }
    return pt;
}

static uint[] SS_P256_P = new uint[] { 0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000001u, 0xFFFFFFFFu };
static uint[] SS_P256_PM2 = new uint[] { 0xFFFFFFFDu, 0xFFFFFFFFu, 0xFFFFFFFFu, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000001u, 0xFFFFFFFFu };
static uint[] SS_P256_GX = new uint[] { 0xD898C296u, 0xF4A13945u, 0x2DEB33A0u, 0x77037D81u, 0x63A440F2u, 0xF8BCE6E5u, 0xE12C4247u, 0x6B17D1F2u };
static uint[] SS_P256_GY = new uint[] { 0x37BF51F5u, 0xCBB64068u, 0x6B315ECEu, 0x2BCE3357u, 0x7C0F9E16u, 0x8EE7EB4Au, 0xFE1A7F9Bu, 0x4FE342E2u };
static uint[] SS_P256_ONE = new uint[] { 1u, 0u, 0u, 0u, 0u, 0u, 0u, 0u };
static uint[] SS_P256_ZERO = new uint[] { 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u };

// 判断 256 位数是否为零
bool SS_U256Zero(uint[] a) { for (int i = 0; i < 8; i++) if (a[i] != 0) return false; return true; }

// 比较两个 256 位数
int SS_U256Cmp(uint[] a, uint[] b)
{
    for (int i = 7; i >= 0; i--)
    {
        if (a[i] > b[i]) return 1;
        if (a[i] < b[i]) return -1;
    }
    return 0;
}

// 大端字节转 256 位数
uint[] SS_U256FromBe(byte[] b, int off)
{
    uint[] r = new uint[8];
    for (int i = 0; i < 8; i++) r[7 - i] = SS_Be32(b, off + i * 4);
    return r;
}

// 256 位数转大端字节
byte[] SS_U256ToBe(uint[] a)
{
    byte[] r = new byte[32];
    for (int i = 0; i < 8; i++) SS_PutBe32(r, (7 - i) * 4, a[i]);
    return r;
}

// 模 P 加法
uint[] SS_PAdd(uint[] a, uint[] b)
{
    uint[] r = new uint[9];
    ulong c = 0;
    for (int i = 0; i < 8; i++)
    {
        ulong s = (ulong)a[i] + b[i] + c;
        r[i] = (uint)s;
        c = s >> 32;
    }
    r[8] = (uint)c;

    while (r[8] != 0 || SS_Cmp9(r, SS_P256_P) >= 0)
    {
        long borrow = 0;
        for (int i = 0; i < 8; i++)
        {
            long v = (long)r[i] - SS_P256_P[i] - borrow;
            if (v < 0) { v += 4294967296L; borrow = 1; } else borrow = 0;
            r[i] = (uint)v;
        }
        r[8] = (uint)((long)r[8] - borrow);
    }

    uint[] o = new uint[8];
    for (int i = 0; i < 8; i++) o[i] = r[i];
    return o;
}

// 比较 9 个 limb 的大小
int SS_Cmp9(uint[] r, uint[] p)
{
    if (r[8] != 0) return 1;
    for (int i = 7; i >= 0; i--)
    {
        if (r[i] > p[i]) return 1;
        if (r[i] < p[i]) return -1;
    }
    return 0;
}

// 模 P 减法
uint[] SS_PSub(uint[] a, uint[] b)
{
    uint[] r = new uint[8];
    long borrow = 0;
    for (int i = 0; i < 8; i++)
    {
        long v = (long)a[i] - b[i] - borrow;
        if (v < 0) { v += 4294967296L; borrow = 1; } else borrow = 0;
        r[i] = (uint)v;
    }
    if (borrow != 0)
    {
        ulong c = 0;
        for (int i = 0; i < 8; i++)
        {
            ulong s = (ulong)r[i] + SS_P256_P[i] + c;
            r[i] = (uint)s;
            c = s >> 32;
        }
    }
    return r;
}

// 512 位结果对 P 取模
uint[] SS_Reduce512(uint[] t)
{
    uint[] r = new uint[16];
    for (int i = 0; i < 16; i++) r[i] = t[i];

    for (int shift = 256; shift >= 0; shift--)
    {
        int w = shift >> 5, bsh = shift & 31;
        while (true)
        {
            uint[] cand = new uint[9];
            for (int j = 0; j < 8; j++)
            {
                uint lo = r[w + j] >> bsh;
                uint hi = 0;
                if (bsh != 0 && (w + j + 1) < 16) hi = r[w + j + 1] << (32 - bsh);
                cand[j] = lo | hi;
            }
            if ((w + 8) < 16) cand[8] = r[w + 8] >> bsh;

            bool ge = cand[8] != 0;
            if (!ge)
            {
                for (int i = 7; i >= 0; i--)
                {
                    if (cand[i] > SS_P256_P[i]) { ge = true; break; }
                    if (cand[i] < SS_P256_P[i]) { ge = false; break; }
                }
            }
            if (!ge) break;

            uint[] tmp = new uint[16];
            for (int i = 0; i < 8; i++)
            {
                tmp[w + i] |= SS_P256_P[i] << bsh;
                if (bsh != 0 && (w + i + 1) < 16) tmp[w + i + 1] |= SS_P256_P[i] >> (32 - bsh);
            }
            long borrow = 0;
            for (int i = 0; i < 16; i++)
            {
                long v = (long)r[i] - tmp[i] - borrow;
                if (v < 0) { v += 4294967296L; borrow = 1; } else borrow = 0;
                r[i] = (uint)v;
            }
        }
    }

    uint[] o = new uint[8];
    for (int i = 0; i < 8; i++) o[i] = r[i];
    return o;
}

// 模 P 乘法
uint[] SS_PMul(uint[] a, uint[] b)
{
    uint[] t = new uint[16];
    for (int i = 0; i < 8; i++)
    {
        ulong carry = 0;
        for (int j = 0; j < 8; j++)
        {
            ulong cur = (ulong)a[i] * b[j] + t[i + j] + carry;
            t[i + j] = (uint)cur;
            carry = cur >> 32;
        }
        t[i + 8] = (uint)carry;
    }
    return SS_Reduce512(t);
}

// 模 P 平方
uint[] SS_PSqr(uint[] a) { return SS_PMul(a, a); }

// 模 P 加倍
uint[] SS_PDbl(uint[] a) { return SS_PAdd(a, a); }

// 乘一个小整数并对 P 取模
uint[] SS_PMulSmall(uint[] a, int k)
{
    uint[] r = SS_P256_ZERO;
    for (int i = 0; i < k; i++) r = SS_PAdd(r, a);
    return r;
}

// 模 P 求逆
uint[] SS_PInv(uint[] a)
{
    uint[] r = new uint[] { 1u, 0u, 0u, 0u, 0u, 0u, 0u, 0u };
    for (int bit = 255; bit >= 0; bit--)
    {
        r = SS_PMul(r, r);
        if (((SS_P256_PM2[bit >> 5] >> (bit & 31)) & 1u) != 0) r = SS_PMul(r, a);
    }
    return r;
}

uint[][] SS_PtInf() { return new uint[][] { new uint[8], new uint[8], new uint[8] }; }

// 判断点是否为无穷远
bool SS_PtIsInf(uint[] Z) { return SS_U256Zero(Z); }

// Jacobian 点倍
uint[][] SS_PtDouble(uint[] X, uint[] Y, uint[] Z)
{
    if (SS_U256Zero(Y)) return SS_PtInf();

    uint[] delta = SS_PSqr(Z);
    uint[] gamma = SS_PSqr(Y);
    uint[] beta = SS_PMul(X, gamma);
    uint[] t1 = SS_PSub(X, delta);
    uint[] t2 = SS_PAdd(X, delta);
    uint[] alpha = SS_PMulSmall(SS_PMul(t1, t2), 3);

    uint[] beta2 = SS_PDbl(beta);
    uint[] beta4 = SS_PDbl(beta2);
    uint[] beta8 = SS_PDbl(beta4);

    uint[] X3 = SS_PSub(SS_PSqr(alpha), beta8);

    uint[] tz = SS_PAdd(Y, Z);
    uint[] Z3 = SS_PSub(SS_PSub(SS_PSqr(tz), gamma), delta);

    uint[] gamma2 = SS_PSqr(gamma);
    uint[] gamma8 = SS_PDbl(SS_PDbl(SS_PDbl(gamma2)));
    uint[] Y3 = SS_PSub(SS_PMul(alpha, SS_PSub(beta4, X3)), gamma8);

    return new uint[][] { X3, Y3, Z3 };
}

// Jacobian 点加
uint[][] SS_PtAdd(uint[] X1, uint[] Y1, uint[] Z1, uint[] X2, uint[] Y2, uint[] Z2)
{
    if (SS_PtIsInf(Z1)) return new uint[][] { X2, Y2, Z2 };
    if (SS_PtIsInf(Z2)) return new uint[][] { X1, Y1, Z1 };

    uint[] Z1Z1 = SS_PSqr(Z1);
    uint[] Z2Z2 = SS_PSqr(Z2);
    uint[] U1 = SS_PMul(X1, Z2Z2);
    uint[] U2 = SS_PMul(X2, Z1Z1);
    uint[] S1 = SS_PMul(SS_PMul(Y1, Z2), Z2Z2);
    uint[] S2 = SS_PMul(SS_PMul(Y2, Z1), Z1Z1);

    uint[] H = SS_PSub(U2, U1);
    uint[] R = SS_PSub(S2, S1);

    if (SS_U256Zero(H))
    {
        if (SS_U256Zero(R)) return SS_PtDouble(X1, Y1, Z1);
        return SS_PtInf();
    }

    uint[] HH = SS_PSqr(H);
    uint[] HHH = SS_PMul(HH, H);
    uint[] V = SS_PMul(U1, HH);

    uint[] X3 = SS_PSub(SS_PSub(SS_PSqr(R), HHH), SS_PDbl(V));
    uint[] Y3 = SS_PSub(SS_PMul(R, SS_PSub(V, X3)), SS_PMul(S1, HHH));
    uint[] Z3 = SS_PMul(SS_PMul(Z1, Z2), H);

    return new uint[][] { X3, Y3, Z3 };
}

// 标量乘
uint[][] SS_PtMul(uint[] k, uint[] X, uint[] Y, uint[] Z)
{
    uint[] rx = new uint[8], ry = new uint[8], rz = new uint[8];
    for (int bit = 255; bit >= 0; bit--)
    {
        uint[][] d = SS_PtDouble(rx, ry, rz);
        rx = d[0]; ry = d[1]; rz = d[2];
        if (((k[bit >> 5] >> (bit & 31)) & 1u) != 0)
        {
            uint[][] a = SS_PtAdd(rx, ry, rz, X, Y, Z);
            rx = a[0]; ry = a[1]; rz = a[2];
        }
    }
    return new uint[][] { rx, ry, rz };
}

// 65 字节公钥转曲线点
uint[][] SS_PtFromPub65(byte[] pub)
{
    if (pub == null || pub.Length != 65 || pub[0] != 0x04) return null;
    uint[] x = SS_U256FromBe(pub, 1);
    uint[] y = SS_U256FromBe(pub, 33);
    return new uint[][] { x, y, new uint[] { 1u, 0u, 0u, 0u, 0u, 0u, 0u, 0u } };
}

// ECDH 求共享点的 X 坐标
byte[] SS_EcdhX(byte[] priv32, byte[] peerPub65)
{
    uint[][] pt = SS_PtFromPub65(peerPub65);
    if (pt == null) return null;

    uint[] k = SS_U256FromBe(priv32, 0);
    uint[][] s = SS_PtMul(k, pt[0], pt[1], pt[2]);
    if (SS_PtIsInf(s[2])) return null;

    uint[] zi = SS_PInv(s[2]);
    uint[] zi2 = SS_PMul(zi, zi);
    uint[] x = SS_PMul(s[0], zi2);
    return SS_U256ToBe(x);
}

// 算 HKDF 用的 info
byte[] SS_CalInfo(byte[] clientPub, byte[] serverPub)
{
    byte[] r = new byte[clientPub.Length];
    for (int i = 0; i < clientPub.Length; i++)
    {
        byte s = serverPub[i % serverPub.Length];
        byte t = (clientPub[i] > s) ? (byte)((s * 2) & 0xFF) : (byte)(s >> 1);
        r[i] = (byte)(clientPub[i] ^ t);
    }
    return r;
}

// 按字段号找第一个字段值
bool SS_PbFind(byte[] d, int want, out int wt, out ulong iv, out byte[] bv)
{
    wt = -1; iv = 0; bv = null;
    if (d == null) return false;

    int p = 0, end = d.Length;
    while (p < end)
    {
        ulong tag;
        if (!SS_Varint(d, ref p, end, out tag)) return false;

        int f = (int)(tag >> 3);
        int w = (int)(tag & 7);
        if (f <= 0) return false;

        if (w == 0)
        {
            ulong v;
            if (!SS_Varint(d, ref p, end, out v)) return false;
            if (f == want) { wt = 0; iv = v; return true; }
        }
        else if (w == 1)
        {
            if (p + 8 > end) return false;
            p += 8;
        }
        else if (w == 5)
        {
            if (p + 4 > end) return false;
            p += 4;
        }
        else if (w == 2)
        {
            ulong l;
            if (!SS_Varint(d, ref p, end, out l)) return false;
            int fl = (int)l;
            if (fl < 0 || p + fl > end) return false;
            if (f == want) { wt = 2; bv = SS_Slice(d, p, fl); return true; }
            p += fl;
        }
        else return false;
    }
    return false;
}

// 用私钥与公钥派生 key3
bool SS_TryDeriveKey3()
{
    if (SS_DerivedKey3 != null) return true;

    byte[] priv = SS_Hex(SS_CLIENT_PRIV_HEX);
    if (priv.Length != 32) return false;
    if (SS_ClientPub == null || SS_ServerPub == null) return false;

    byte[] shared = SS_EcdhX(priv, SS_ServerPub);
    if (shared == null) return false;

    byte[] ikm = new byte[32];
    int n = shared.Length < 32 ? shared.Length : 32;
    for (int i = 0; i < n; i++) ikm[32 - n + i] = shared[shared.Length - n + i];

    byte[] k = SS_Hkdf32(ikm, SS_ServerPub, SS_CalInfo(SS_ClientPub, SS_ServerPub));
    if (k == null || k.Length != 32) return false;

    SS_DerivedKey3 = k;
    return true;
}

// 缓存 IKE 报文里的公钥与参数
void SS_IkeCapture(byte[] body, bool isReq)
{
    int wt;
    ulong iv;
    byte[] bv;

    if (isReq)
    {
        if (SS_PbFind(body, 3, out wt, out iv, out bv) && bv != null && bv.Length > 0)
        {
            bool replaced = SS_MitmF1Pub != null && SS_SameBytes(bv, SS_MitmF1Pub) && SS_MitmCliPub != null;
            if (!replaced) SS_ClientPub = bv;
        }
        return;
    }

    if (SS_PbFind(body, 1, out wt, out iv, out bv) && bv != null) SS_IkeToken = SS_Utf8String(bv);
    if (SS_PbFind(body, 2, out wt, out iv, out bv)) SS_IkeCipher = (int)iv;
    if (SS_PbFind(body, 3, out wt, out iv, out bv)) SS_IkeServerTs = (long)iv;
    if (SS_PbFind(body, 4, out wt, out iv, out bv) && bv != null && bv.Length > 0)
    {
        bool replaced = SS_MitmF2Pub != null && SS_SameBytes(bv, SS_MitmF2Pub) && SS_MitmSrvPub != null;
        if (!replaced) SS_ServerPub = bv;
    }

    SS_TryDeriveKey3();
}

// 按算法编号解密
byte[] SS_AeadDec(byte[] key, byte[] nonce, byte[] ct, byte[] tag, byte[] aad, int fn)
{
    if (aad == null) aad = new byte[0];
    if (fn == 1) return SS_ChachaDec(key, nonce, ct, tag, aad);
    return SS_GcmDec(key, nonce, ct, tag, aad);
}

// 用指定密钥尝试解密
byte[] SS_TryAead(byte[] buf, byte[] key, int fn, bool aadNonce)
{
    if (buf == null || key == null || buf.Length < 12 + 16 + 2) return null;
    byte[] nonce = SS_Slice(buf, 0, 12);
    int ctLen = buf.Length - 12 - 16;
    byte[] ct = SS_Slice(buf, 12, ctLen);
    byte[] tag = SS_Slice(buf, buf.Length - 16, 16);
    byte[] aad = aadNonce ? nonce : new byte[0];
    return SS_AeadDec(key, nonce, ct, tag, aad, fn);
}

// IKE 报文四种混淆变换
byte[] SS_Transform(byte[] wire, int t, byte[] garble)
{
    byte[] d = SS_Slice(wire, 0, wire.Length);
    if (t == 0) return d;

    if (garble == null || garble.Length == 0) return null;

    if (t == 1 || t == 2)
    {
        for (int i = 0; i < d.Length; i++)
        {
            if (t == 1) d[i] = SS_Ror1(d[i]);
            else d[i] ^= garble[i % garble.Length];
        }
        for (int i = 0; i < d.Length; i++)
        {
            if (t == 1) d[i] ^= garble[i % garble.Length];
            else d[i] = SS_Ror1(d[i]);
        }
        return d;
    }

    byte lb = (byte)(wire.Length & 0xFF);
    for (int i = 0; i < d.Length; i++)
    {
        d[i] ^= lb;
        d[i] = (t == 3) ? SS_Ror1(d[i]) : SS_Rol1(d[i]);
        d[i] ^= garble[i % garble.Length];
    }
    return d;
}

// AES-GCM 加密
byte[] SS_GcmEnc(byte[] key, byte[] nonce, byte[] pt, byte[] aad)
{
    if (key == null || (key.Length != 16 && key.Length != 32)) return null;
    if (nonce == null || nonce.Length != 12) return null;

    uint[] rk;
    int nr = SS_AesExpand(key, out rk);

    byte[] hb = new byte[16];
    SS_AesEncBlock(rk, nr, hb);
    ulong h0 = 0, h1 = 0;
    for (int i = 0; i < 8; i++) h0 = (h0 << 8) | hb[i];
    for (int i = 8; i < 16; i++) h1 = (h1 << 8) | hb[i];

    byte[] j0 = new byte[16];
    for (int i = 0; i < 12; i++) j0[i] = nonce[i];
    j0[15] = 1;

    byte[] ct = new byte[pt.Length];
    byte[] ctr = new byte[16];
    for (int i = 0; i < 16; i++) ctr[i] = j0[i];
    for (int off = 0; off < pt.Length; off += 16)
    {
        for (int i = 15; i >= 12; i--) { ctr[i] = (byte)(ctr[i] + 1); if (ctr[i] != 0) break; }
        byte[] ks = new byte[16];
        for (int i = 0; i < 16; i++) ks[i] = ctr[i];
        SS_AesEncBlock(rk, nr, ks);
        int n = pt.Length - off; if (n > 16) n = 16;
        for (int i = 0; i < n; i++) ct[off + i] = (byte)(pt[off + i] ^ ks[i]);
    }

    ulong y0 = 0, y1 = 0;
    for (int off = 0; off < aad.Length; off += 16) SS_GHashBlock(ref y0, ref y1, aad, off, aad.Length, h0, h1);
    for (int off = 0; off < ct.Length; off += 16) SS_GHashBlock(ref y0, ref y1, ct, off, ct.Length, h0, h1);
    y0 ^= (ulong)aad.Length * 8;
    y1 ^= (ulong)ct.Length * 8;
    SS_GMul(ref y0, ref y1, h0, h1);

    byte[] ej = new byte[16];
    for (int i = 0; i < 16; i++) ej[i] = j0[i];
    SS_AesEncBlock(rk, nr, ej);

    byte[] r = new byte[ct.Length + 16];
    for (int i = 0; i < ct.Length; i++) r[i] = ct[i];
    for (int i = 0; i < 8; i++) r[ct.Length + i] = (byte)(ej[i] ^ (byte)(y0 >> (8 * (7 - i))));
    for (int i = 0; i < 8; i++) r[ct.Length + 8 + i] = (byte)(ej[8 + i] ^ (byte)(y1 >> (8 * (7 - i))));
    return r;
}

// ChaCha20-Poly1305 加密
byte[] SS_ChachaEnc(byte[] key, byte[] nonce, byte[] pt, byte[] aad)
{
    if (key == null || key.Length != 32) return null;
    if (nonce == null || nonce.Length != 12) return null;

    uint[] st = new uint[16];
    st[0] = 0x61707865u; st[1] = 0x3320646eu; st[2] = 0x79622d32u; st[3] = 0x6b206574u;
    for (int i = 0; i < 8; i++) st[4 + i] = SS_Le32(key, i * 4);
    st[12] = 0;
    st[13] = SS_Le32(nonce, 0); st[14] = SS_Le32(nonce, 4); st[15] = SS_Le32(nonce, 8);

    byte[] polyKey64 = new byte[64];
    SS_ChaBlock(st, polyKey64, 0);
    byte[] polyKey = new byte[32];
    for (int i = 0; i < 32; i++) polyKey[i] = polyKey64[i];

    byte[] ct = new byte[pt.Length];
    byte[] ks = new byte[64];
    uint counter = 1;
    for (int off = 0; off < pt.Length; off += 64)
    {
        st[12] = counter++;
        SS_ChaBlock(st, ks, 0);
        int n = pt.Length - off; if (n > 64) n = 64;
        for (int i = 0; i < n; i++) ct[off + i] = (byte)(pt[off + i] ^ ks[i]);
    }

    int aadPad = (aad.Length % 16 == 0) ? 0 : 16 - (aad.Length % 16);
    int ctPad = (ct.Length % 16 == 0) ? 0 : 16 - (ct.Length % 16);
    byte[] mac = new byte[aad.Length + aadPad + ct.Length + ctPad + 16];
    int p = 0;
    for (int i = 0; i < aad.Length; i++) mac[p++] = aad[i];
    p += aadPad;
    for (int i = 0; i < ct.Length; i++) mac[p++] = ct[i];
    p += ctPad;
    ulong al = (ulong)aad.Length, cl = (ulong)ct.Length;
    for (int i = 0; i < 8; i++) { mac[p + i] = (byte)(al >> (8 * i)); mac[p + 8 + i] = (byte)(cl >> (8 * i)); }
    byte[] tag = SS_Poly1305(polyKey, mac);

    byte[] r = new byte[ct.Length + 16];
    for (int i = 0; i < ct.Length; i++) r[i] = ct[i];
    for (int i = 0; i < 16; i++) r[ct.Length + i] = tag[i];
    return r;
}

// 按算法编号加密
byte[] SS_AeadEnc(byte[] key, byte[] nonce, byte[] pt, byte[] aad, int fn)
{
    if (aad == null) aad = new byte[0];
    if (fn == 1) return SS_ChachaEnc(key, nonce, pt, aad);
    return SS_GcmEnc(key, nonce, pt, aad);
}

// IKE 请求混淆变体一
void SS_ObscureReq(byte[] d, byte[] g)
{
    for (int i = 0; i < d.Length; i++)
    {
        d[i] ^= g[i % g.Length];
        d[i] = SS_Rol1(d[i]);
    }
}

// IKE 响应混淆变体一
void SS_ObscureResp(byte[] d, byte[] g)
{
    byte lb = (byte)(d.Length & 0xFF);
    for (int i = 0; i < d.Length; i++)
    {
        d[i] ^= g[i % g.Length];
        d[i] = SS_Rol1(d[i]);
        d[i] ^= lb;
    }
}

// IKE 请求混淆变体二
void SS_ObscureReq2(byte[] d, byte[] g)
{
    for (int i = 0; i < d.Length; i++)
    {
        d[i] = SS_Rol1(d[i]);
        d[i] ^= g[i % g.Length];
    }
}

// IKE 响应混淆变体二
void SS_ObscureResp2(byte[] d, byte[] g)
{
    byte lb = (byte)(d.Length & 0xFF);
    for (int i = 0; i < d.Length; i++)
    {
        d[i] ^= g[i % g.Length];
        d[i] = SS_Ror1(d[i]);
        d[i] ^= lb;
    }
}

// 按字段号找字段的偏移与长度
bool SS_PbOff(byte[] d, int start, int end, int want, out int off, out int len)
{
    off = -1; len = 0;
    int p = start;
    while (p < end)
    {
        int sp = p;
        ulong tag;
        if (!SS_Varint(d, ref p, end, out tag)) return false;
        int f = (int)(tag >> 3);
        int w = (int)(tag & 7);
        if (f <= 0) return false;

        if (w == 0)
        {
            ulong v;
            if (!SS_Varint(d, ref p, end, out v)) return false;
        }
        else if (w == 1)
        {
            if (p + 8 > end) return false;
            p += 8;
        }
        else if (w == 5)
        {
            if (p + 4 > end) return false;
            p += 4;
        }
        else if (w == 2)
        {
            ulong l;
            if (!SS_Varint(d, ref p, end, out l)) return false;
            int fl = (int)l;
            if (fl < 0 || p + fl > end) return false;
            if (f == want) { off = p; len = fl; return true; }
            p += fl;
        }
        else return false;

        if (p <= sp) return false;
    }
    return false;
}

// 由私钥算公钥
byte[] SS_PubOfPriv(byte[] priv32)
{
    if (priv32 == null || priv32.Length != 32) return null;
    uint[] k = SS_U256FromBe(priv32, 0);
    if (SS_U256Zero(k)) return null;

    uint[][] s = SS_PtMul(k, SS_P256_GX, SS_P256_GY, SS_P256_ONE);
    if (SS_PtIsInf(s[2])) return null;

    uint[] zi = SS_PInv(s[2]);
    uint[] zi2 = SS_PMul(zi, zi);
    uint[] zi3 = SS_PMul(zi2, zi);
    byte[] x = SS_U256ToBe(SS_PMul(s[0], zi2));
    byte[] y = SS_U256ToBe(SS_PMul(s[1], zi3));

    byte[] r = new byte[65];
    r[0] = 0x04;
    for (int i = 0; i < 32; i++) { r[1 + i] = x[i]; r[33 + i] = y[i]; }
    return r;
}

// 按客户端算法算 key3
byte[] SS_K3(byte[] priv32, byte[] peerPub65, byte[] cliPub65, byte[] srvPub65)
{
    if (priv32 == null || priv32.Length != 32) return null;
    if (peerPub65 == null || peerPub65.Length != 65) return null;
    if (cliPub65 == null || cliPub65.Length != 65) return null;
    if (srvPub65 == null || srvPub65.Length != 65) return null;

    byte[] sh = SS_EcdhX(priv32, peerPub65);
    if (sh == null) return null;

    byte[] ikm = new byte[32];
    int n = sh.Length < 32 ? sh.Length : 32;
    for (int i = 0; i < n; i++) ikm[32 - n + i] = sh[sh.Length - n + i];

    byte[] k = SS_Hkdf32(ikm, srvPub65, SS_CalInfo(cliPub65, srvPub65));
    if (k == null || k.Length != 32) return null;
    return k;
}

// 取当前区服的 garble key
byte[] SS_GarbleBytes()
{
    string gk;
    if (SS_GARBLE.TryGetValue(SS_REGION, out gk) && gk != null && gk.Length > 0)
        return SS_AsciiBytes(gk);
    return new byte[0];
}

// 初始化中转密钥对并算出 F1 F2 公钥
void SS_MitmInit()
{
    if (SS_MitmF1Pub != null && SS_MitmF2Pub != null) return;

    byte[] p1 = SS_Hex(SS_F1_PRIV_HEX);
    byte[] p2 = SS_Hex(SS_F2_PRIV_HEX);
    if (p1.Length != 32 || p2.Length != 32) return;

    SS_MitmF1Pub = SS_PubOfPriv(p1);
    SS_MitmF2Pub = SS_PubOfPriv(p2);
}

// 改写 IKE 报文里的公钥
byte[] SS_MitmIke(byte[] wire, byte[] g, bool isReq, out int msgId, out byte[] realPub, out string note)
{
    msgId = 0; realPub = null; note = null;
    if (wire == null || wire.Length < 30) return null;

    byte[] pt = null;
    byte[] nonce = null;
    int fn = -1, tr = 0, ctLen = 0;
    string aadName = null;

    int[] tvars = new int[] { 3, 1, 4, 2 };
    for (int ti = 0; ti < tvars.Length && pt == null; ti++)
    {
        int cur = tvars[ti];
        byte[] d = SS_Transform(wire, cur, g);
        if (d == null || d.Length < 30) continue;

        byte[] n = SS_Slice(d, 0, 12);
        int cl = d.Length - 12 - 16;
        if (cl < 2) continue;
        byte[] ct = SS_Slice(d, 12, cl);
        byte[] tag = SS_Slice(d, d.Length - 16, 16);

        for (int ai = 0; ai < 2 && pt == null; ai++)
        {
            byte[] aad = ai == 0 ? n : new byte[0];
            for (int f = 0; f < 2; f++)
            {
                int cand = (SS_IkeCipher == 1) ? (f == 0 ? 1 : 0) : (f == 0 ? 0 : 1);
                byte[] r = SS_AeadDec(g, n, ct, tag, aad, cand);
                if (r != null && r.Length >= 5 && SS_BE16(r, 0) == (isReq ? 1 : 2))
                {
                    pt = r; fn = cand; tr = cur; nonce = n; ctLen = cl;
                    aadName = (ai == 0 ? "nonce" : "none");
                    break;
                }
            }
        }
    }
    if (pt == null) return null;

    msgId = SS_BE16(pt, 0);

    int want = isReq ? 3 : 4;
    int off, len;
    if (!SS_PbOff(pt, 2, pt.Length, want, out off, out len)) return null;
    if (len != 65) return null;
    if (pt[off] != 0x04) return null;

    realPub = SS_Slice(pt, off, 65);

    byte[] mine = isReq ? SS_MitmF1Pub : SS_MitmF2Pub;
    if (mine == null || mine.Length != 65) return null;
    for (int i = 0; i < 65; i++) pt[off + i] = mine[i];

    byte[] body = SS_AeadEnc(g, nonce, pt, aadName == "nonce" ? nonce : new byte[0], fn);
    if (body == null || body.Length != ctLen + 16) return null;

    byte[] w2 = new byte[12 + body.Length];
    for (int i = 0; i < 12; i++) w2[i] = nonce[i];
    for (int i = 0; i < body.Length; i++) w2[12 + i] = body[i];

    if (tr == 1) SS_ObscureReq(w2, g);
    else if (tr == 2) SS_ObscureReq2(w2, g);
    else if (tr == 3) SS_ObscureResp(w2, g);
    else SS_ObscureResp2(w2, g);

    note = (isReq ? "clientPubKey" : "serverPubKey") + " replaced, fn="
         + (fn == 1 ? "chacha" : "aes-gcm") + " aad=" + aadName + " t=" + SS_IntStr(tr);
    return w2;
}

// 解密后换 key 重加密业务报文
byte[] SS_MitmRelay(byte[] wire, bool isReq, byte[] g)
{
    if (SS_MitmKCli == null || SS_MitmKSrv == null) return null;
    if (wire == null || wire.Length < 30) return null;

    byte[] keyIn = isReq ? SS_MitmKCli : SS_MitmKSrv;
    byte[] keyOut = isReq ? SS_MitmKSrv : SS_MitmKCli;
    int[] tvars = new int[] { 0, 3, 1, 4, 2 };

    for (int ti = 0; ti < tvars.Length; ti++)
    {
        byte[] d = SS_Transform(wire, tvars[ti], g);
        if (d == null || d.Length < 30) continue;

        byte[] nonce = SS_Slice(d, 0, 12);
        int ctLen = d.Length - 12 - 16;
        if (ctLen < 2) continue;
        byte[] ct = SS_Slice(d, 12, ctLen);
        byte[] tag = SS_Slice(d, d.Length - 16, 16);

        for (int ai = 0; ai < 2; ai++)
        {
            byte[] aad = ai == 0 ? nonce : new byte[0];
            for (int f = 0; f < 2; f++)
            {
                int fn = (SS_IkeCipher == 1) ? (f == 0 ? 1 : 0) : (f == 0 ? 0 : 1);
                byte[] pt = SS_AeadDec(keyIn, nonce, ct, tag, aad, fn);
                if (pt == null) continue;

                byte[] body = SS_AeadEnc(keyOut, nonce, pt, aad, fn);
                if (body == null || body.Length != ctLen + 16) return null;

                byte[] r = new byte[12 + body.Length];
                for (int i = 0; i < 12; i++) r[i] = nonce[i];
                for (int i = 0; i < body.Length; i++) r[12 + i] = body[i];

                if (tvars[ti] == 1) SS_ObscureReq(r, g);
                else if (tvars[ti] == 2) SS_ObscureReq2(r, g);
                else if (tvars[ti] == 3) SS_ObscureResp(r, g);
                else if (tvars[ti] == 4) SS_ObscureResp2(r, g);

                SS_MitmRelayCnt++;
                return r;
            }
        }
    }
    return null;
}

// 中转模式主入口
void SS_MitmStep(Session s, bool isReq, ref byte[] wire, System.Text.StringBuilder sb,
                 byte[] chunkTpl, int[] cOff, int[] cLen)
{
    try
    {
        SS_MitmInit();
        if (SS_MitmF1Pub == null || SS_MitmF2Pub == null)
        {
            sb.Append("MITM   = disabled, invalid F1/F2 private key\n");
            return;
        }

        byte[] g = SS_GarbleBytes();
        if (g.Length == 0)
        {
            sb.Append("MITM   = disabled, no garble key for region\n");
            return;
        }

        byte[] outp = null;
        int mid = 0;
        byte[] realPub = null;
        string note = null;
        bool relayed = false;
        byte[] pendingCliPub = null;

        if (SS_MitmKCli != null && SS_MitmKSrv != null)
        {
            outp = SS_MitmRelay(wire, isReq, g);
            relayed = (outp != null);
        }

        if (outp == null)
        {
            if (!isReq && SS_MitmCliPub == null)
            {
                sb.Append("MITM   = skip IKE response, matching request not seen\n");
                return;
            }

            outp = SS_MitmIke(wire, g, isReq, out mid, out realPub, out note);
            if (outp != null)
            {
                if (isReq)
                {
                    pendingCliPub = realPub;
                    sb.Append("MITM   = ").Append(note).Append('\n');
                    sb.Append("         real clientPub = ").Append(SS_HexStr(realPub)).Append('\n');
                    sb.Append("         replaced with F1_pub = ").Append(SS_HexStr(SS_MitmF1Pub)).Append('\n');
                }
                else
                {
                    SS_MitmSrvPub = realPub;
                    sb.Append("MITM   = ").Append(note).Append('\n');
                    sb.Append("         real serverPub = ").Append(SS_HexStr(realPub)).Append('\n');
                    sb.Append("         replaced with F2_pub = ").Append(SS_HexStr(SS_MitmF2Pub)).Append('\n');

                    byte[] p1 = SS_Hex(SS_F1_PRIV_HEX);
                    byte[] p2 = SS_Hex(SS_F2_PRIV_HEX);
                    if (SS_MitmCliPub != null && SS_MitmCliPub.Length == 65 && realPub.Length == 65)
                    {
                        SS_MitmKCli = SS_K3(p2, SS_MitmCliPub, SS_MitmCliPub, SS_MitmF2Pub);
                        SS_MitmKSrv = SS_K3(p1, realPub, SS_MitmF1Pub, realPub);
                    }
                    if (SS_MitmKCli != null && SS_MitmKSrv != null)
                    {
                        sb.Append("         key3 client side = ").Append(SS_HexStr(SS_MitmKCli)).Append('\n');
                        sb.Append("         key3 server side = ").Append(SS_HexStr(SS_MitmKSrv)).Append('\n');
                        sb.Append("         => relay ready, packets decrypted and re-encrypted\n");
                    }
                    else
                    {
                        sb.Append("         => key3 failed, IKE request must be captured too\n");
                        SS_MitmFail++;
                    }
                }
            }
        }

        if (outp == null)
        {
            if (!relayed && SS_MitmKCli == null && !SS_MitmWarned)
            {
                SS_MitmWarned = true;
                sb.Append("MITM   = not taken over, handshake already done before Fiddler start\n")
                  .Append("         reason: clientPubKey never seen, Fiddler started too late\n")
                  .Append("         fix: restart the game so handshake happens with Fiddler ready\n");
            }
            return;
        }

        try
        {
            byte[] toWrite = outp;
            if (chunkTpl != null)
            {
                toWrite = SS_Rechunk(chunkTpl, outp, cOff, cLen);
                if (toWrite == null)
                {
                    SS_MitmFail++;
                    if (!isReq) { SS_MitmKCli = null; SS_MitmKSrv = null; }
                    sb.Append("MITM   = chunked rebuild failed, packet passed through\n");
                    return;
                }
            }

            if (isReq) s.requestBodyBytes = toWrite;
            else s.responseBodyBytes = toWrite;
            wire = outp;

            if (pendingCliPub != null) SS_MitmCliPub = pendingCliPub;
            if (relayed)
                sb.Append("MITM   = relayed ").Append(isReq ? "client to server" : "server to client")
                  .Append(", total ").Append(SS_IntStr(SS_MitmRelayCnt)).Append(" packets\n");
        }
        catch
        {
            SS_MitmFail++;
            if (!isReq)
            {
                SS_MitmKCli = null; SS_MitmKSrv = null;
            }
            sb.Append("MITM   = write back failed, packet passed through\n");
        }
    }
    catch
    {
        SS_MitmFail++;
    }
}

// 解密报文并拆出 msgId 与正文
bool SS_Decode(byte[] wire, bool isReq, out int msgId, out byte[] body, out string info, out byte[] plain)
{
    msgId = 0; body = null; info = null; plain = null;
    if (wire == null || wire.Length < 30) return false;

    byte[] garble = new byte[0];
    string gkey;
    if (SS_GARBLE.TryGetValue(SS_REGION, out gkey) && gkey != null && gkey.Length > 0)
        garble = SS_AsciiBytes(gkey);

    byte[] key3 = SS_Hex(SS_KEY3_LIVE.Length == 64 ? SS_KEY3_LIVE : SS_KEY3_HEX);
    if (key3.Length != 32) key3 = null;
    if (key3 == null && garble.Length == 0 && SS_MitmKCli == null) return false;

    var keys = new System.Collections.Generic.List<byte[]>();
    var knm = new System.Collections.Generic.List<string>();
    if (key3 != null) { keys.Add(key3); knm.Add(SS_KEY3_LIVE.Length == 64 ? "key3@" : "key3"); }
    SS_TryDeriveKey3();
    if (SS_DerivedKey3 != null) { keys.Add(SS_DerivedKey3); knm.Add("key3*"); }
    if (SS_MitmKCli != null) { keys.Add(SS_MitmKCli); knm.Add("k3C"); }
    if (SS_MitmKSrv != null) { keys.Add(SS_MitmKSrv); knm.Add("k3S"); }
    if (garble.Length > 0) { keys.Add(garble); knm.Add("garble"); }

    int[] fnOrder = (SS_IkeCipher == 1) ? new int[] { 1, 0 } : new int[] { 0, 1 };

    int[] order = new int[] { 0, 3, 4, 1, 2 };
    string[] tname = new string[] { "raw", "req.ror", "req.alt", "resp.ror", "resp.alt" };

    for (int oi = 0; oi < order.Length; oi++)
    {
        int t = order[oi];
        byte[] d = SS_Transform(wire, t, garble);
        if (d == null) continue;

        for (int ki = 0; ki < keys.Count; ki++)
        {
            byte[] key = keys[ki];
            if (key == null || key.Length == 0) continue;

            for (int fi = 0; fi < 2; fi++)
            {
                int fn = fnOrder[fi];
                for (int ai = 0; ai < 2; ai++)
                {
                    byte[] pt = SS_TryAead(d, key, fn, ai == 0);
                    if (pt == null || pt.Length < 2) continue;

                    int id, bodyOff;
                    if (isReq)
                    {
                        if (SS_BE16(pt, 0) == 1) { id = 1; bodyOff = 2; }
                        else if (pt.Length >= 12) { id = SS_BE16(pt, 10); bodyOff = 12; }
                        else continue;
                    }
                    else
                    {
                        id = SS_BE16(pt, 0); bodyOff = 2;
                    }
                    if (id <= 0) continue;

                    msgId = id;
                    body = SS_Slice(pt, bodyOff, pt.Length - bodyOff);
                    info = "t=" + tname[t]
                         + " key=" + knm[ki]
                         + " fn=" + (fn == 1 ? "chacha" : "aes-gcm")
                         + " aad=" + (ai == 0 ? "nonce" : "none");
                    SS_LastKey = key;
                    SS_LastKeyName = knm[ki];
                    SS_LastNonce = SS_Slice(d, 0, d.Length < 12 ? d.Length : 12);
                    SS_LastResolved = null;
                    plain = pt;
                    return true;
                }
            }
        }
    }
    return false;
}

// 判断字节串是否为可读文本
bool SS_IsPrintable(byte[] b)
{
    if (b == null || b.Length == 0) return false;
    for (int i = 0; i < b.Length; i++)
    {
        byte c = b[i];
        if (c == 9 || c == 10 || c == 13) continue;
        if (c >= 32 && c < 127) continue;
        if (c >= 0x80) continue;
        return false;
    }
    return SS_Utf8Valid(b, 0, b.Length);
}

// 读一个 varint
bool SS_Varint(byte[] d, ref int p, int end, out ulong v)
{
    v = 0; int shift = 0;
    while (p < end && shift < 64)
    {
        byte b = d[p++];
        v |= ((ulong)(b & 0x7F)) << shift;
        if ((b & 0x80) == 0) return true;
        shift += 7;
    }
    return false;
}

// JSON 字符串转义
string SS_JsonEsc(string s)
{
    if (s == null) return "";
    var sb = new System.Text.StringBuilder(s.Length + 8);
    foreach (char c in s)
    {
        int v = (int)c;
        if (c == '"') sb.Append("\\\"");
        else if (c == '\\') sb.Append("\\\\");
        else if (c == '\n') sb.Append("\\n");
        else if (c == '\r') sb.Append("\\r");
        else if (c == '\t') sb.Append("\\t");
        else if (v < 0x20 || v == 0x7F)
            sb.Append("\\u00").Append(SS_HexChar((v >> 4) & 0xF)).Append(SS_HexChar(v & 0xF));
        else sb.Append(c);
    }
    return sb.ToString();
}

// 追加一个 UTF-8 码点
void SS_Utf8Append3(System.Collections.Generic.List<byte> o, int cp)
{
    o.Add((byte)(0xE0 | (cp >> 12)));
    o.Add((byte)(0x80 | ((cp >> 6) & 0x3F)));
    o.Add((byte)(0x80 | (cp & 0x3F)));
}

// 字符串转 UTF-8 字节
byte[] SS_Utf8Bytes(string s)
{
    if (s == null) return new byte[0];
    var o = new System.Collections.Generic.List<byte>(s.Length + 16);
    int hi = -1;

    foreach (char ch in s)
    {
        int cp = (int)ch;

        if (cp >= 0xD800 && cp <= 0xDBFF) { hi = cp; continue; }
        if (cp >= 0xDC00 && cp <= 0xDFFF && hi >= 0)
        {
            int full = 0x10000 + ((hi - 0xD800) << 10) + (cp - 0xDC00);
            hi = -1;
            o.Add((byte)(0xF0 | (full >> 18)));
            o.Add((byte)(0x80 | ((full >> 12) & 0x3F)));
            o.Add((byte)(0x80 | ((full >> 6) & 0x3F)));
            o.Add((byte)(0x80 | (full & 0x3F)));
            continue;
        }
        if (hi >= 0) { SS_Utf8Append3(o, hi); hi = -1; }

        if (cp < 0x80) o.Add((byte)cp);
        else if (cp < 0x800)
        {
            o.Add((byte)(0xC0 | (cp >> 6)));
            o.Add((byte)(0x80 | (cp & 0x3F)));
        }
        else SS_Utf8Append3(o, cp);
    }
    if (hi >= 0) SS_Utf8Append3(o, hi);

    byte[] r = new byte[o.Count];
    for (int i = 0; i < o.Count; i++) r[i] = o[i];
    return r;
}

// 输出二进制字段的十六进制
void SS_JsonHexOut(byte[] d, int off, int len, System.Text.StringBuilder sb)
{
    int show = len;
    if (show > 128) show = 128;
    sb.Append('"');
    for (int i = 0; i < show; i++)
    {
        int b = d[off + i] & 0xFF;
        sb.Append(SS_HexChar((b >> 4) & 0xF)).Append(SS_HexChar(b & 0xF));
    }
    if (len > show) sb.Append("…(").Append(SS_IntStr(len)).Append("B)");
    sb.Append('"');
}

// 展开 Any 的 type_url 与 value
void SS_JsonAny(byte[] d, int off, int len, System.Text.StringBuilder sb, int depth)
{
    string url = null;
    int vOff = -1, vLen = 0;

    var fns = new System.Collections.Generic.List<int>();
    var wts = new System.Collections.Generic.List<int>();
    var vos = new System.Collections.Generic.List<int>();
    var vls = new System.Collections.Generic.List<int>();
    if (SS_ScanFields(d, off, len, fns, wts, vos, vls))
    {
        for (int i = 0; i < fns.Count; i++)
        {
            if (wts[i] != 2) continue;
            if (fns[i] == 1) url = SS_Utf8String(SS_Slice(d, vos[i], vls[i]));
            else if (fns[i] == 2) { vOff = vos[i]; vLen = vls[i]; }
        }
    }

    string tname = null;
    if (url != null && url.Length > 0)
    {
        int sl = url.LastIndexOf('/');
        tname = (sl >= 0) ? url.Substring(sl + 1, url.Length - sl - 1) : url;
        int dot = tname.LastIndexOf('.');
        if (dot >= 0) tname = tname.Substring(dot + 1, tname.Length - dot - 1);
    }

    sb.Append('{');
    if (url != null) sb.Append("\"@type\":\"").Append(SS_JsonEsc(url)).Append('"');

    if (vOff >= 0 && vLen > 0 && depth < 12)
    {
        var tmp = new System.Text.StringBuilder();
        bool ok = (tname != null) && SS_JsonMsg(d, vOff, vLen, tmp, depth + 1, tname);
        if (!ok)
        {
            tmp = new System.Text.StringBuilder();
            ok = SS_JsonMsg(d, vOff, vLen, tmp, depth + 1, null);
        }

        if (url != null) sb.Append(',');
        if (ok) sb.Append("\"value\":").Append(tmp.ToString());
        else { sb.Append("\"value\":"); SS_JsonHexOut(d, vOff, vLen, sb); }
    }
    sb.Append('}');
}

// 展开 NextPackage 里的续包
void SS_JsonNext(byte[] d, int off, int len, System.Text.StringBuilder sb, int depth, string ownerType)
{
    int skip = -1;
    for (int k = 0; k <= 2; k++)
    {
        if (len - k < 2) continue;
        var a = new System.Collections.Generic.List<int>();
        var b = new System.Collections.Generic.List<int>();
        var c = new System.Collections.Generic.List<int>();
        var e = new System.Collections.Generic.List<int>();
        if (SS_ScanFields(d, off + k, len - k, a, b, c, e)) { skip = k; break; }
    }
    if (skip < 0) { SS_JsonHexOut(d, off, len, sb); return; }

    var tmp = new System.Text.StringBuilder();
    bool ok = false;
    if (ownerType != null && depth < 10)
        ok = SS_JsonMsg(d, off + skip, len - skip, tmp, depth + 1, ownerType);
    if (!ok)
    {
        tmp = new System.Text.StringBuilder();
        ok = SS_JsonMsg(d, off + skip, len - skip, tmp, depth + 1, null);
    }
    if (ok) sb.Append(tmp.ToString());
    else SS_JsonHexOut(d, off, len, sb);
}

// 输出单个字段的值
void SS_JsonVal(byte[] d, int wt, int vo, int vl, string sub, string code,
                System.Text.StringBuilder sb, int depth, string ownerType)
{
    if (sub != null && wt == 2)
    {
        if (sub == "Any") { SS_JsonAny(d, vo, vl, sb, depth); return; }
        var st = new System.Text.StringBuilder();
        if (SS_JsonMsg(d, vo, vl, st, depth + 1, sub)) { sb.Append(st.ToString()); return; }
    }

    if (wt == 2 && sub == null && code == null)
    {
        var st2 = new System.Text.StringBuilder();
        if (SS_JsonMsg(d, vo, vl, st2, depth + 1, null)) { sb.Append(st2.ToString()); return; }
    }

    if (wt == 0)
    {
        ulong nv = SS_VarintAt(d, vo, vl);
        char bt0 = SS_CodeBase(code);
        if (bt0 == 'i') { sb.Append(SS_LongStr((long)(int)(uint)nv)); return; }
        if (bt0 == 'l') { sb.Append(SS_LongStr((long)nv)); return; }
        if (nv > 9223372036854775807UL) { sb.Append(SS_LongStr((long)nv)); return; }
        sb.Append(SS_UIntStr(nv, 10));
        return;
    }
    if (wt == 1 || wt == 5)
    {
        ulong v = 0;
        for (int i = vl - 1; i >= 0; i--) v = (v << 8) | d[vo + i];
        sb.Append(SS_UIntStr(v, 10));
        return;
    }

    char baseT = SS_CodeBase(code);

    if (SS_CodeIsRepeated(code) && (baseT == 'i' || baseT == 'l' || baseT == 'u' || baseT == 'f' || baseT == 'd'))
    {
        var vals = new System.Collections.Generic.List<ulong>(vl + 1);
        int cnt = SS_PackedVals(d, vo, vl, baseT, vals, 100000);
        if (cnt > 0)
        {
            sb.Append('[');
            for (int i = 0; i < vals.Count; i++)
            {
                if (i > 0) sb.Append(',');
                if (baseT == 'i') sb.Append(SS_LongStr((long)(int)(uint)vals[i]));
                else if (baseT == 'l') sb.Append(SS_LongStr((long)vals[i]));
                else sb.Append(SS_UIntStr(vals[i], 10));
            }
            if (cnt > vals.Count) sb.Append(",…");
            sb.Append(']');
            return;
        }
    }

    if (baseT == 's')
    {
        if (SS_Utf8Valid(d, vo, vl))
        {
            sb.Append('"').Append(SS_JsonEsc(SS_Utf8String(SS_Slice(d, vo, vl)))).Append('"');
            return;
        }
        SS_JsonHexOut(d, vo, vl, sb);
        return;
    }

    if (baseT == 'b') { SS_JsonHexOut(d, vo, vl, sb); return; }

    byte[] val = SS_Slice(d, vo, vl);
    if (SS_IsPrintable(val))
    {
        sb.Append('"').Append(SS_JsonEsc(SS_Utf8String(val))).Append('"');
        return;
    }
    SS_JsonHexOut(d, vo, vl, sb);
}

// 输出一个字段项
void SS_JsonItem(byte[] d, int i,
                 System.Collections.Generic.List<int> fns,
                 System.Collections.Generic.List<int> wts,
                 System.Collections.Generic.List<int> vos,
                 System.Collections.Generic.List<int> vls,
                 string sub, string code,
                 System.Text.StringBuilder sb, int depth, string ownerType)
{
    if (fns[i] == 2047 && wts[i] == 2) { SS_JsonNext(d, vos[i], vls[i], sb, depth, ownerType); return; }
    SS_JsonVal(d, wts[i], vos[i], vls[i], sub, code, sb, depth, ownerType);
}

// 猜类型时排除的占位消息与静态资源消息
static string[] SS_GUESS_SKIP = new string[]
{
    "Nil", "Error", "Any", "Empty", "Ping", "Pong",
    "UI32", "I32", "UI64", "I64", "S32", "S64", "StringV", "Bytes", "BytesV", "Boolean",
    "ServerListMeta", "ServerAgent", "Rule", "NoticeList", "NoticeType", "NoticeItem"
};

static System.Collections.Generic.Dictionary<string, int[]>    SS_GNUM   = null;
static System.Collections.Generic.Dictionary<string, string[]> SS_GCODE  = null;
static System.Collections.Generic.Dictionary<string, string>   SS_GCACHE = null;

// 判断是否为占位消息
bool SS_GuessSkip(string n)
{
    if (n == null) return true;
    for (int i = 0; i < SS_GUESS_SKIP.Length; i++) if (SS_GUESS_SKIP[i] == n) return true;
    return false;
}

// 预解析每条消息的字段号与类型码
void SS_EnsureGuessIdx()
{
    if (SS_GNUM != null) return;
    SS_GNUM = new System.Collections.Generic.Dictionary<string, int[]>();
    SS_GCODE = new System.Collections.Generic.Dictionary<string, string[]>();
    SS_GCACHE = new System.Collections.Generic.Dictionary<string, string>();

    foreach (string mn in SS_SCHEMA.Keys)
    {
        string sp;
        if (!SS_SCHEMA.TryGetValue(mn, out sp)) continue;

        var ns = new System.Collections.Generic.List<int>();
        var cs = new System.Collections.Generic.List<string>();
        char[] sc = SS_Chars(sp);
        int n = sc.Length, p = 0;

        while (p < n)
        {
            int comma = n;
            for (int i = p; i < n; i++) if (sc[i] == ',') { comma = i; break; }

            int c1 = -1, c2 = -1;
            for (int i = p; i < comma; i++)
            {
                if (sc[i] != ':') continue;
                if (c1 < 0) c1 = i;
                else { c2 = i; break; }
            }

            if (c1 > p)
            {
                int num = 0; bool ok = true;
                for (int i = p; i < c1; i++)
                {
                    char c = sc[i];
                    if (c < '0' || c > '9') { ok = false; break; }
                    num = num * 10 + (c - '0');
                }
                if (ok)
                {
                    ns.Add(num);
                    cs.Add(c2 > c1 ? sp.Substring(c2 + 1, comma - c2 - 1) : null);
                }
            }
            p = comma + 1;
        }

        int[] na = new int[ns.Count];
        string[] ca = new string[cs.Count];
        for (int i = 0; i < ns.Count; i++) { na[i] = ns[i]; ca[i] = cs[i]; }
        SS_GNUM[mn] = na;
        SS_GCODE[mn] = ca;
    }
}

// 判断类型码与 wire 类型是否相容
bool SS_CodeMatch(string code, int wt)
{
    if (code == null) return false;
    int p = 0;
    if (SS_Ch0(code) == 'r') p = 1;
    char c = SS_ChAt(code, p);
    if (c == '>' || c == 'm') return wt == 2;
    if (wt == 0) return c == 'i' || c == 'l' || c == 'u';
    if (wt == 1) return c == 'd';
    if (wt == 5) return c == 'f';
    return c == 's' || c == 'b';
}

// 统计字段表里没有的字段号个数
int SS_MissCount(string spec, System.Collections.Generic.List<int> fns)
{
    if (spec == null) return fns.Count;
    int miss = 0;
    string nm, sub, cd;
    for (int i = 0; i < fns.Count; i++)
    {
        SS_SchemaField(spec, fns[i], out nm, out sub, out cd);
        if (nm == null) miss++;
    }
    return miss;
}

// 递归给候选类型打分，返回 -1 表示明显不匹配
int SS_GuessScore(string typeName, byte[] d, int off, int len, int depth)
{
    if (depth > 3) return 0;

    string spec;
    if (typeName == null || !SS_SCHEMA.TryGetValue(typeName, out spec)) return -1;

    var fns = new System.Collections.Generic.List<int>();
    var wts = new System.Collections.Generic.List<int>();
    var vos = new System.Collections.Generic.List<int>();
    var vls = new System.Collections.Generic.List<int>();
    if (!SS_ScanFields(d, off, len, fns, wts, vos, vls)) return -1;

    int score = 0;
    for (int i = 0; i < fns.Count; i++)
    {
        string nm, sub, cd;
        SS_SchemaField(spec, fns[i], out nm, out sub, out cd);
        if (nm == null) { score -= 1; continue; }
        if (sub != null) { if (wts[i] != 2) return -1; }
        else if (!SS_CodeMatch(cd, wts[i])) return -1;
        if (sub == null && cd != null && SS_Ch0(cd) == 's' && wts[i] == 2 && !SS_Utf8Valid(d, vos[i], vls[i])) return -1;
        score += 2;

        if (wts[i] == 2 && sub != null && sub != "Any" && vls[i] > 1)
        {
            int s2 = SS_GuessScore(sub, d, vos[i], vls[i], depth + 1);
            if (s2 < 0) return -1;
            score += s2;
        }
    }
    return score;
}

// 按字段号与 wire 类型猜消息类型，得分唯一最高才采用
string SS_SchemaGuess(byte[] d, int off, int len, System.Collections.Generic.List<int> fns, System.Collections.Generic.List<int> wts)
{
    SS_EnsureSchema();
    SS_EnsureGuessIdx();

    var un = new System.Collections.Generic.List<int>();
    var uw = new System.Collections.Generic.List<int>();
    for (int i = 0; i < fns.Count; i++)
    {
        bool dup = false;
        for (int k = 0; k < un.Count; k++) if (un[k] == fns[i]) { dup = true; break; }
        if (!dup) { un.Add(fns[i]); uw.Add(wts[i]); }
    }

    var sigb = new System.Text.StringBuilder();
    for (int i = 0; i < un.Count; i++)
    {
        if (i > 0) sigb.Append(',');
        sigb.Append(SS_IntStr(un[i])).Append('_').Append(SS_IntStr(uw[i]));
    }
    sigb.Append('#').Append(SS_IntStr(len));
    string sig = sigb.ToString();

    string cached;
    if (SS_GCACHE.TryGetValue(sig, out cached)) return (cached.Length == 0) ? null : cached;

    string best = null;
    int bestScore = -1;
    int bestCnt = 0;

    foreach (string mn in SS_GNUM.Keys)
    {
        if (SS_GuessSkip(mn)) continue;

        int[] nums;
        if (!SS_GNUM.TryGetValue(mn, out nums)) continue;
        if (nums.Length < un.Count) continue;
        if (nums.Length - un.Count > 2) continue;

        string[] codes;
        SS_GCODE.TryGetValue(mn, out codes);
        if (codes == null) continue;

        bool ok = true;
        for (int i = 0; i < un.Count && ok; i++)
        {
            int j = -1;
            for (int k = 0; k < nums.Length; k++) if (nums[k] == un[i]) { j = k; break; }
            if (j < 0 || !SS_CodeMatch(codes[j], uw[i])) ok = false;
        }
        if (!ok) continue;

        int sc = SS_GuessScore(mn, d, off, len, 0);
        if (sc < 0) continue;

        if (sc > bestScore) { bestScore = sc; bestCnt = 1; best = mn; }
        else if (sc == bestScore) bestCnt++;
    }

    if (bestCnt != 1) best = null;
    SS_GCACHE[sig] = best == null ? "" : best;
    return best;
}

// 把一个消息输出成 JSON
bool SS_JsonMsg(byte[] d, int off, int len, System.Text.StringBuilder sb, int depth, string typeName)
{
    if (depth > 12) return false;

    string spec = null;
    SS_EnsureSchema();
    if (typeName != null && typeName.Length > 0) SS_SCHEMA.TryGetValue(typeName, out spec);

    var fns = new System.Collections.Generic.List<int>();
    var wts = new System.Collections.Generic.List<int>();
    var vos = new System.Collections.Generic.List<int>();
    var vls = new System.Collections.Generic.List<int>();
    if (!SS_ScanFields(d, off, len, fns, wts, vos, vls)) return false;

    if (fns.Count > 0 && (spec == null || SS_GuessSkip(typeName)))
    {
        int miss = SS_MissCount(spec, fns);
        if (miss > 0)
        {
            string g = SS_SchemaGuess(d, off, len, fns, wts);
            if (g != null)
            {
                string gs;
                if (SS_SCHEMA.TryGetValue(g, out gs) && SS_MissCount(gs, fns) < miss)
                {
                    spec = gs;
                    typeName = g;
                    if (depth == 0) SS_LastResolved = g;
                }
            }
        }
    }

    var order = new System.Collections.Generic.List<string>();
    var subs  = new System.Collections.Generic.Dictionary<string, string>();
    var codes = new System.Collections.Generic.Dictionary<string, string>();
    var grp   = new System.Collections.Generic.Dictionary<string, System.Collections.Generic.List<int>>();

    for (int i = 0; i < fns.Count; i++)
    {
        string nm = null, sub = null, cd = null;
        if (spec != null) SS_SchemaField(spec, fns[i], out nm, out sub, out cd);
        string key = (nm != null) ? nm : SS_IntStr(fns[i]);

        System.Collections.Generic.List<int> g;
        if (!grp.TryGetValue(key, out g))
        {
            g = new System.Collections.Generic.List<int>();
            grp[key] = g;
            order.Add(key);
            subs[key] = sub;
            codes[key] = cd;
        }
        g.Add(i);
    }

    sb.Append('{');
    for (int gi = 0; gi < order.Count; gi++)
    {
        string key = order[gi];
        if (gi > 0) sb.Append(',');

        string sub = null, cd = null;
        subs.TryGetValue(key, out sub);
        codes.TryGetValue(key, out cd);
        var g = grp[key];

        bool forceArr = (cd != null && cd.Length >= 2 && SS_ChAt(cd, 0) == 'r'
                         && (SS_ChAt(cd, 1) == 'm' || SS_ChAt(cd, 1) == 's' || SS_ChAt(cd, 1) == 'b'));

        sb.Append('"').Append(SS_JsonEsc(key)).Append("\":");
        if (g.Count == 1 && !forceArr)
        {
            SS_JsonItem(d, g[0], fns, wts, vos, vls, sub, cd, sb, depth, typeName);
        }
        else
        {
            sb.Append('[');
            for (int k = 0; k < g.Count; k++)
            {
                if (k > 0) sb.Append(',');
                SS_JsonItem(d, g[k], fns, wts, vos, vls, sub, cd, sb, depth, typeName);
            }
            sb.Append(']');
        }
    }
    sb.Append('}');
    return order.Count > 0;
}

// 按消息名输出完整 JSON
string SS_JsonBody(byte[] body, string typeName)
{
    if (body == null || body.Length == 0) return null;
    var sb = new System.Text.StringBuilder(body.Length * 3 + 64);
    if (!SS_JsonMsg(body, 0, body.Length, sb, 0, typeName)) return null;
    return sb.ToString();
}

// 读指定位置的 varint
ulong SS_VarintAt(byte[] d, int p, int len)
{
    ulong v = 0;
    int sh = 0;
    for (int i = 0; i < len && i < 10; i++)
    {
        v |= (ulong)(d[p + i] & 0x7F) << sh;
        sh += 7;
    }
    return v;
}

// 扫描一条消息的全部字段
bool SS_ScanFields(byte[] d, int off, int len,
                   System.Collections.Generic.List<int> fns,
                   System.Collections.Generic.List<int> wts,
                   System.Collections.Generic.List<int> vos,
                   System.Collections.Generic.List<int> vls)
{
    int p = off, end = off + len;
    while (p < end)
    {
        int mark = p;
        ulong tag;
        if (!SS_Varint(d, ref p, end, out tag)) return false;

        int fn = (int)(tag >> 3);
        int wt = (int)(tag & 7);
        if (fn == 0) return false;

        int vo, vl;
        if (wt == 0)
        {
            ulong v;
            vo = p;
            if (!SS_Varint(d, ref p, end, out v)) return false;
            vl = p - vo;
        }
        else if (wt == 1)
        {
            if (p + 8 > end) return false;
            vo = p; vl = 8; p += 8;
        }
        else if (wt == 5)
        {
            if (p + 4 > end) return false;
            vo = p; vl = 4; p += 4;
        }
        else if (wt == 2)
        {
            ulong l;
            if (!SS_Varint(d, ref p, end, out l)) return false;
            if (l > (ulong)(end - p)) return false;
            vo = p; vl = (int)l; p += vl;
        }
        else
        {
            return false;
        }

        fns.Add(fn); wts.Add(wt); vos.Add(vo); vls.Add(vl);
        if (p <= mark) return false;
    }
    return fns.Count > 0;
}

static string SS_SCHEMA_META =
    "ServerAgent|1:name:s,2:addr:s,3:status:i,4:zone:l\n" +
    "Rule|1:platform:u,2:channel:s,3:version:s,4:op:u,5:action:u,6:url:s,7:enable:u\n" +
    "ServerListMeta|1:version:l,2:agent:r>ServerAgent,3:status:i,4:message:s,6:report_endpoint:s,7:rules:r>Rule\n" +
    "NoticeItem|1:id:u,2:title:s,3:content_url:s,4:channel:ru,5:quest_id:s,6:end_time:l,7:sort:l\n" +
    "NoticeType|1:name:s,2:detail:r>NoticeItem\n" +
    "NoticeList|1:list:r>NoticeType\n";

static string[] SS_REGION_ORDER = new string[] { "CN", "EN", "JP", "KR", "TW" };

// 按路径判断静态资源类型
string SS_StaticKind(Session s)
{
    string path = SS_PathOf(s);
    if (path.IndexOf("serverlist.html") >= 0) return "ServerListMeta";
    if (path.IndexOf("noticelist.html") >= 0) return "NoticeList";
    return null;
}

// 判断会话是否为静态资源
bool SS_IsStaticMeta(Session s)
{
    try
    {
        if (SS_StaticKind(s) == null) return false;
        string host = SS_HostOf(s);
        if (host.IndexOf("static") >= 0) return true;
        return SS_STATIC_HOSTREGION.ContainsKey(host);
    }
    catch { return false; }
}

// 按域名判断静态资源区服
string SS_StaticRegion(Session s)
{
    string host = SS_HostOf(s);
    string r;
    if (SS_STATIC_HOSTREGION.TryGetValue(host, out r)) return r;
    return SS_REGION;
}

static byte[] SS_InfSrc;
static int    SS_InfPos;
static int    SS_InfBit;
static System.Collections.Generic.List<byte> SS_InfOut;

// 重置 inflate 输入状态
void SS_InfReset(byte[] src, int start)
{
    SS_InfSrc = src;
    SS_InfPos = start;
    SS_InfBit = 0;
    SS_InfOut = new System.Collections.Generic.List<byte>(src.Length * 3 + 64);
}

// 读 n 位
int SS_InfBits(int n)
{
    int v = 0;
    for (int i = 0; i < n; i++)
    {
        if (SS_InfPos >= SS_InfSrc.Length) return v;
        int b = (SS_InfSrc[SS_InfPos] >> SS_InfBit) & 1;
        v |= b << i;
        SS_InfBit++;
        if (SS_InfBit == 8) { SS_InfBit = 0; SS_InfPos++; }
    }
    return v;
}

// 对齐到字节边界
void SS_InfAlign()
{
    if (SS_InfBit != 0) { SS_InfBit = 0; SS_InfPos++; }
}

// 由码长表建 Huffman 表
void SS_HuffBuild(int[] lengths, int n, int[] counts, int[] syms)
{
    for (int i = 0; i <= 15; i++) counts[i] = 0;
    for (int i = 0; i < n; i++) counts[lengths[i]]++;
    counts[0] = 0;

    int[] offs = new int[16];
    offs[1] = 0;
    for (int i = 1; i < 15; i++) offs[i + 1] = offs[i] + counts[i];
    for (int i = 0; i < n; i++)
        if (lengths[i] != 0) syms[offs[lengths[i]]++] = i;
}

// 解码一个 Huffman 符号
int SS_HuffDec(int[] counts, int[] syms, int maxLen)
{
    int code = 0, first = 0, index = 0;
    for (int len = 1; len <= maxLen; len++)
    {
        code |= SS_InfBits(1);
        int cnt = counts[len];
        if (code - first < cnt) return syms[index + (code - first)];
        index += cnt;
        first = (first + cnt) << 1;
        code <<= 1;
    }
    return -1;
}

static int[] SS_LEN_BASE  = new int[] { 3,4,5,6,7,8,9,10,11,13,15,17,19,23,27,31,35,43,51,59,67,83,99,115,131,163,195,227,258 };
static int[] SS_LEN_EXTRA = new int[] { 0,0,0,0,0,0,0,0,1,1,1,1,2,2,2,2,3,3,3,3,4,4,4,4,5,5,5,5,0 };
static int[] SS_DIST_BASE = new int[] { 1,2,3,4,5,7,9,13,17,25,33,49,65,97,129,193,257,385,513,769,1025,1537,2049,3073,4097,6145,8193,12289,16385,24577 };
static int[] SS_DIST_EXTRA= new int[] { 0,0,0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7,8,8,9,9,10,10,11,11,12,12,13,13 };

// 解一个 deflate 块
bool SS_InfBlock(int[] litC, int[] litS, int litMax, int[] distC, int[] distS, int distMax)
{
    while (true)
    {
        int sym = SS_HuffDec(litC, litS, litMax);
        if (sym < 0) return false;
        if (sym < 256) { SS_InfOut.Add((byte)sym); continue; }
        if (sym == 256) return true;

        int li = sym - 257;
        if (li < 0 || li > 28) return false;
        int len = SS_LEN_BASE[li] + SS_InfBits(SS_LEN_EXTRA[li]);

        int ds = SS_HuffDec(distC, distS, distMax);
        if (ds < 0 || ds > 29) return false;
        int dist = SS_DIST_BASE[ds] + SS_InfBits(SS_DIST_EXTRA[ds]);
        if (dist <= 0 || dist > SS_InfOut.Count) return false;

        int from = SS_InfOut.Count - dist;
        for (int k = 0; k < len; k++) SS_InfOut.Add(SS_InfOut[from + k]);
    }
}

// 解 deflate 流
byte[] SS_Inflate()
{
    int[] litC = new int[16], distC = new int[16];
    int[] litS = new int[320], distS = new int[32];

    bool last = false;
    while (!last)
    {
        last = SS_InfBits(1) != 0;
        int type = SS_InfBits(2);

        if (type == 0)
        {
            SS_InfAlign();
            int len = SS_InfBits(16);
            SS_InfBits(16);
            for (int i = 0; i < len && SS_InfPos < SS_InfSrc.Length; i++)
                SS_InfOut.Add(SS_InfSrc[SS_InfPos++]);
            continue;
        }

        if (type == 1)
        {
            var lens = new int[288];
            for (int i = 0; i < 144; i++) lens[i] = 8;
            for (int i = 144; i < 256; i++) lens[i] = 9;
            for (int i = 256; i < 280; i++) lens[i] = 7;
            for (int i = 280; i < 288; i++) lens[i] = 8;
            SS_HuffBuild(lens, 288, litC, litS);

            var dl = new int[32];
            for (int i = 0; i < 32; i++) dl[i] = 5;
            SS_HuffBuild(dl, 32, distC, distS);

            if (!SS_InfBlock(litC, litS, 9, distC, distS, 5)) return null;
            continue;
        }

        if (type == 2)
        {
            int hlit  = SS_InfBits(5) + 257;
            int hdist = SS_InfBits(5) + 1;
            int hclen = SS_InfBits(4) + 4;
            if (hlit > 286 || hdist > 30) return null;

            int[] order = new int[] { 16,17,18,0,8,7,9,6,10,5,11,4,12,3,13,2,14,1,15 };
            var clen = new int[19];
            for (int i = 0; i < hclen; i++) clen[order[i]] = SS_InfBits(3);

            int[] cc = new int[16], cs = new int[19];
            SS_HuffBuild(clen, 19, cc, cs);
            int cmax = 1;
            for (int i = 15; i >= 1; i--) if (cc[i] != 0) { cmax = i; break; }

            var lens = new int[hlit + hdist];
            int p = 0;
            while (p < lens.Length)
            {
                int sym = SS_HuffDec(cc, cs, cmax);
                if (sym < 0) return null;
                if (sym < 16) { lens[p++] = sym; continue; }

                int rep, val = 0;
                if (sym == 16) { if (p == 0) return null; val = lens[p - 1]; rep = 3 + SS_InfBits(2); }
                else if (sym == 17) { rep = 3 + SS_InfBits(3); }
                else { rep = 11 + SS_InfBits(7); }
                if (p + rep > lens.Length) return null;
                for (int k = 0; k < rep; k++) lens[p++] = val;
            }

            var ll = new int[hlit];
            var dd = new int[hdist];
            for (int i = 0; i < hlit; i++) ll[i] = lens[i];
            for (int i = 0; i < hdist; i++) dd[i] = lens[hlit + i];

            SS_HuffBuild(ll, hlit, litC, litS);
            SS_HuffBuild(dd, hdist, distC, distS);

            int lmax = 1, dmax = 1;
            for (int i = 15; i >= 1; i--) if (litC[i] != 0) { lmax = i; break; }
            for (int i = 15; i >= 1; i--) if (distC[i] != 0) { dmax = i; break; }

            if (!SS_InfBlock(litC, litS, lmax, distC, distS, dmax)) return null;
            continue;
        }

        return null;
    }

    int n = SS_InfOut.Count;
    var res = new byte[n];
    for (int i = 0; i < n; i++) res[i] = SS_InfOut[i];
    return res;
}

// 解 gzip 容器
byte[] SS_Gunzip(byte[] d, int off)
{
    if (d == null || d.Length - off < 18) return null;
    if (d[off] != 0x1F || d[off + 1] != 0x8B || d[off + 2] != 0x08) return null;

    int flg = d[off + 3];
    int p = off + 10;

    if ((flg & 0x04) != 0)
    {
        if (p + 2 > d.Length) return null;
        int xlen = d[p] | (d[p + 1] << 8);
        p += 2 + xlen;
    }
    if ((flg & 0x08) != 0) { while (p < d.Length && d[p] != 0) p++; p++; }
    if ((flg & 0x10) != 0) { while (p < d.Length && d[p] != 0) p++; p++; }
    if ((flg & 0x02) != 0) p += 2;
    if (p >= d.Length) return null;

    SS_InfReset(d, p);
    return SS_Inflate();
}

// 判断是否为 zlib 容器
bool SS_LooksZlib(byte[] d)
{
    if (d == null || d.Length < 6 || d[0] != 0x78) return false;
    return (((d[0] << 8) | d[1]) % 31) == 0;
}

// 解 zlib 容器
byte[] SS_ZlibUnzip(byte[] d)
{
    if (!SS_LooksZlib(d)) return null;
    SS_InfReset(d, 2);
    return SS_Inflate();
}

// 计算 CRC32
uint SS_Crc32(byte[] d, int off, int len)
{
    uint crc = 0xFFFFFFFFu;
    for (int i = 0; i < len; i++)
    {
        crc ^= d[off + i];
        for (int k = 0; k < 8; k++)
            crc = ((crc & 1) != 0) ? ((crc >> 1) ^ 0xEDB88320u) : (crc >> 1);
    }
    return crc ^ 0xFFFFFFFFu;
}

// 把数据封成 gzip
byte[] SS_GzipWrap(byte[] data)
{
    int n = (data == null) ? 0 : data.Length;
    int blocks = (n + 65534) / 65535;
    if (blocks == 0) blocks = 1;

    var o = new byte[10 + n + blocks * 5 + 8];
    int p = 0;
    o[p++] = 0x1F; o[p++] = 0x8B; o[p++] = 0x08; o[p++] = 0x00;
    o[p++] = 0; o[p++] = 0; o[p++] = 0; o[p++] = 0;
    o[p++] = 0;
    o[p++] = 0xFF;

    int done = 0;
    do
    {
        int len = n - done;
        if (len > 65535) len = 65535;
        bool last = (done + len >= n);
        o[p++] = (byte)(last ? 1 : 0);
        o[p++] = (byte)(len & 0xFF);
        o[p++] = (byte)((len >> 8) & 0xFF);
        int nlen = (~len) & 0xFFFF;
        o[p++] = (byte)(nlen & 0xFF);
        o[p++] = (byte)((nlen >> 8) & 0xFF);
        for (int i = 0; i < len; i++) o[p++] = data[done + i];
        done += len;
    } while (done < n);

    uint crc = SS_Crc32(data, 0, n);
    o[p++] = (byte)(crc & 0xFF);
    o[p++] = (byte)((crc >> 8) & 0xFF);
    o[p++] = (byte)((crc >> 16) & 0xFF);
    o[p++] = (byte)((crc >> 24) & 0xFF);
    o[p++] = (byte)(n & 0xFF);
    o[p++] = (byte)((n >> 8) & 0xFF);
    o[p++] = (byte)((n >> 16) & 0xFF);
    o[p++] = (byte)((n >> 24) & 0xFF);
    return o;
}

// 判断字节能否整段解析成 protobuf
bool SS_PbFullyParses(byte[] d)
{
    if (d == null || d.Length == 0) return false;
    var a = new System.Collections.Generic.List<int>();
    var b = new System.Collections.Generic.List<int>();
    var c = new System.Collections.Generic.List<int>();
    var e = new System.Collections.Generic.List<int>();
    return SS_ScanFields(d, 0, d.Length, a, b, c, e);
}

// 解密静态资源并返回明文
byte[] SS_StaticPlain(byte[] wire, string region)
{
    try
    {
        if (wire == null || wire.Length < 32) return null;

        int[] co, cl;
        byte[] inner;
        if (SS_TryDechunk(wire, out inner, out co, out cl)) wire = inner;

        if (wire.Length > 2 && wire[0] == 0x1F && wire[1] == 0x8B)
        {
            byte[] un = SS_Gunzip(wire, 0);
            if (un != null) wire = un;
        }
        else if (SS_LooksZlib(wire))
        {
            byte[] un = SS_ZlibUnzip(wire);
            if (un != null) wire = un;
        }

        if (wire.Length < 32) return null;

        var iv = new byte[16];
        for (int i = 0; i < 16; i++) iv[i] = wire[i];
        int ctn = wire.Length - 16;
        var ct = new byte[ctn];
        for (int i = 0; i < ctn; i++) ct[i] = wire[16 + i];

        for (int k = -1; k < SS_REGION_ORDER.Length; k++)
        {
            string r = (k < 0) ? region : SS_REGION_ORDER[k];
            if (r == null) continue;
            if (k >= 0 && r == region) continue;

            string key;
            if (!SS_STATIC_KEYS.TryGetValue(r, out key)) continue;
            if (key == null || key.Length == 0) continue;

            byte[] pt = SS_AesCbcDec(SS_AsciiBytes(key), iv, ct);
            if (pt != null && SS_PbFullyParses(pt)) return pt;
        }
        return null;
    }
    catch { return null; }
}

// 标记静态资源会话
void SS_HandleStaticMeta(Session s)
{
    try { s["ui-color"] = "blue"; } catch { }
}

// 把数据封成单段 chunked
byte[] SS_ChunkWrap(byte[] d)
{
    int n = (d == null) ? 0 : d.Length;
    if (n == 0) return SS_AsciiBytes("0\r\n\r\n");

    var digits = new int[8];
    int cnt = 0, v = n;
    while (v > 0) { digits[cnt++] = v & 15; v >>= 4; }

    var hb = new System.Text.StringBuilder();
    for (int i = cnt - 1; i >= 0; i--) hb.Append(SS_HexChar(digits[i]));
    hb.Append("\r\n");

    byte[] pre = SS_AsciiBytes(hb.ToString());
    var o = new byte[pre.Length + n + 7];
    int p = 0;
    for (int i = 0; i < pre.Length; i++) o[p++] = pre[i];
    for (int i = 0; i < n; i++) o[p++] = d[i];
    o[p++] = 13; o[p++] = 10;
    o[p++] = 48; o[p++] = 13; o[p++] = 10; o[p++] = 13; o[p++] = 10;
    return o;
}

// 把静态资源明文写回 body
void SS_WriteStaticBody(Session s)
{
    try
    {
        string kind = SS_StaticKind(s);
        if (kind == null) return;

        byte[] wire = s.responseBodyBytes;
        if (wire == null || wire.Length < 32) return;

        byte[] body = SS_StaticPlain(wire, SS_StaticRegion(s));
        if (body == null) return;

        if (SS_UI_BODY == 0) return;

        bool wasChunked = false, wasGzip = false;
        int[] co, cl;
        byte[] inner;
        byte[] probe = wire;
        if (SS_TryDechunk(probe, out inner, out co, out cl)) { probe = inner; wasChunked = true; }
        if (probe.Length > 2 && probe[0] == 0x1F && probe[1] == 0x8B) wasGzip = true;

        string js = null;
        if (SS_UI_BODY == 2)
        {
            js = SS_JsonBody(body, kind);
            if (js != null && js.Length > SS_UI_BODY_MAX) js = null;
        }

        byte[] payload = (js != null) ? SS_Utf8Bytes(js) : body;
        if (wasGzip) payload = SS_GzipWrap(payload);
        if (wasChunked) payload = SS_ChunkWrap(payload);

        if (!wasGzip && !wasChunked && js != null)
        {
            try { s.utilSetResponseBody(js); } catch { }
        }

        s.responseBodyBytes = payload;
        try { s["ui-color"] = "blue"; s["ui-bold"] = "true"; } catch { }
    }
    catch { }
}

// 取会话主机名
string SS_HostOf(Session s)
{
    try { return (s.hostname ?? "").ToLower(); } catch { return ""; }
}

// 取会话路径
string SS_PathOf(Session s)
{
    try { return (s.PathAndQuery ?? "").ToLower(); } catch { return ""; }
}

// 判断会话是否为游戏报文
bool SS_IsGameSession(Session s)
{
    try
    {
        string host = SS_HostOf(s);
        string path = SS_PathOf(s);

        if (host.Contains("static") || host.Contains("cdn") || host.Contains("assets")) return false;

        bool hostOk = host.Contains("yostar") || host.Contains("stellasora")
                   || host.Contains("stargazer") || host.Contains("jvav") || host.Contains("nova.");
        bool pathOk = path.Contains("agent-zone");
        if (!hostOk && !pathOk) return false;

        byte[] req = s.requestBodyBytes;
        byte[] rsp = s.responseBodyBytes;
        byte[] b = (req != null && req.Length >= 30) ? req : rsp;
        if (b == null || b.Length < 30) return false;
        if (b[0] == 0x1F && b[1] == 0x8B) return false;
        if (b[0] == 0x7B && (b[1] == 0x22 || b[1] == 0x0A)) return false;
        if (b[0] == 0x3C) return false;

        return true;
    }
    catch { }
    return false;
}

// 判断报文本身是否为明文文本
bool SS_LooksPlain(byte[] b)
{
    if (b == null || b.Length < 64) return false;

    byte f = b[0];
    if (f != 0x24 && f != 0x7B && f != 0x5B && f != 0x3C && f != 0x22 && f != 0x2F) return false;

    int n = b.Length < 4096 ? b.Length : 4096;
    int txt = 0;
    for (int i = 0; i < n; i++)
    {
        byte c = b[i];
        if (c == 9 || c == 10 || c == 13 || (c >= 32 && c < 127)) txt++;
    }
    return txt * 10 >= n * 9;
}

// 接收外部注入的 key3
bool SS_TryFeedKey3(Session s)
{
    string host = SS_HostOf(s);
    string path = SS_PathOf(s);
    bool isFeed = (host.IndexOf("ss-key3") >= 0) || (path.IndexOf("__ss_k3") >= 0);
    if (!isFeed) return false;

    string hex = "";
    try
    {
        byte[] b = s.requestBodyBytes;
        if (b != null && b.Length > 0)
        {
            var sb = new System.Text.StringBuilder(b.Length);
            for (int i = 0; i < b.Length; i++)
            {
                byte c = b[i];
                if (c == 32 || c == 9 || c == 10 || c == 13) continue;
                sb.Append((char)c);
            }
            hex = sb.ToString();
        }
    }
    catch { }

    bool ok = (hex.Length == 64);
    if (ok) SS_KEY3_LIVE = hex;

    try
    {
        s["ui-color"] = ok ? "green" : "red";
    }
    catch { }
    if (!ok) SS_Note(s, "SS key3 inject failed, body len = " + SS_IntStr(hex.Length));
    return true;
}

// 写一行诊断到 Comments
void SS_Note(Session s, string text)
{
    if (!SS_NOTE_FAIL) return;
    try { s["ui-comments"] = text; } catch { }
}

// 追加一行 msgId nonce key3
void SS_LineInfo(System.Text.StringBuilder sb, bool isReq, int msgId)
{
    string nm = SS_MsgName(msgId);
    if (sb.Length > 0) sb.Append('\n');
    sb.Append(isReq ? "REQ " : "RESP").Append("  msgId=").Append(SS_IntStr(msgId))
      .Append(" (").Append(nm).Append(')');

    if (SS_LastResolved != null && SS_LastResolved != nm)
        sb.Append("  type=").Append(SS_LastResolved);

    if (SS_LastNonce != null && SS_LastNonce.Length > 0)
        sb.Append("  nonce=").Append(SS_HexStr(SS_LastNonce));

    if (SS_LastKey != null && SS_LastKey.Length > 0)
    {
        sb.Append("  key3=").Append(SS_HexStr(SS_LastKey));
        if (SS_LastKeyName != null) sb.Append(" [").Append(SS_LastKeyName).Append(']');
    }
}

// 追加一行解码失败
void SS_LineFail(System.Text.StringBuilder sb, bool isReq, byte[] wire, Session s)
{
    if (sb.Length > 0) sb.Append('\n');
    sb.Append(isReq ? "REQ " : "RESP").Append("  decode failed  len=")
      .Append(SS_IntStr(wire.Length)).Append("  host=").Append(SS_HostOf(s));
}

// 判断字符串是否以指定前缀开头
bool SS_Prefix(string s, string p)
{
    if (s == null || p == null || s.Length < p.Length) return false;
    for (int i = 0; i < p.Length; i++) if (SS_ChAt(s, i) != SS_ChAt(p, i)) return false;
    return true;
}

// 按方向写一行注释，同方向已有则替换
void SS_PutLine(Session s, bool isReq, string line)
{
    if (!SS_COMMENT_INFO || line == null) return;

    string prev = null;
    try { prev = s["ui-comments"]; } catch { }

    string tag = isReq ? "REQ" : "RESP";
    var sb = new System.Text.StringBuilder();
    bool placed = false;

    int n = (prev == null) ? 0 : prev.Length;
    int p = 0;
    while (p < n)
    {
        int e = prev.IndexOf('\n', p);
        if (e < 0) e = n;
        string ln = prev.Substring(p, e - p);
        if (SS_Prefix(ln, tag))
        {
            if (!placed) { if (sb.Length > 0) sb.Append('\n'); sb.Append(line); placed = true; }
        }
        else
        {
            if (sb.Length > 0) sb.Append('\n');
            sb.Append(ln);
        }
        p = e + 1;
    }

    if (!placed)
    {
        if (sb.Length > 0) sb.Append('\n');
        sb.Append(line);
    }

    try { s["ui-comments"] = sb.ToString(); } catch { }
}

// 请求与响应的公共流程
void SS_Handle(Session s, bool isReq)
{
    try
    {
        if (isReq && SS_TryFeedKey3(s)) return;

        if (!isReq && SS_STATIC_META && SS_IsStaticMeta(s)) { SS_HandleStaticMeta(s); return; }

        if (!SS_IsGameSession(s)) return;

        byte[] wire = isReq ? s.requestBodyBytes : s.responseBodyBytes;
        if (wire == null || wire.Length < 30) return;
        if (SS_LooksPlain(wire)) return;

        byte[] chunkTpl = null;
        int[] cOff = null, cLen = null;
        byte[] inner;
        if (SS_TryDechunk(wire, out inner, out cOff, out cLen))
        {
            chunkTpl = wire;
            wire = inner;
            if (SS_LooksPlain(wire)) return;
        }

        var mitmSb = new System.Text.StringBuilder();
        if (SS_MITM) SS_MitmStep(s, isReq, ref wire, mitmSb, chunkTpl, cOff, cLen);

        int msgId;
        byte[] body, plain;
        string info;

        if (!SS_Decode(wire, isReq, out msgId, out body, out info, out plain))
            return;

        if (isReq && msgId == 1) SS_IkeCapture(body, true);
        else if (!isReq && msgId == 2) SS_IkeCapture(body, false);

        var cb = new System.Text.StringBuilder();
        SS_LineInfo(cb, isReq, msgId);
        SS_PutLine(s, isReq, cb.ToString());

        if (SS_MARK_COLOR)
        {
            try { s["ui-color"] = "purple"; s["ui-bold"] = "true"; } catch { }
        }
    }
    catch { }
}

// 算出要写回 body 的明文
byte[] SS_PlainOf(byte[] wire, bool isReq, out int msgId, out string typeName, out string text)
{
    msgId = 0; typeName = null; text = null;
    try
    {
        if (wire == null || wire.Length < 30) return null;

        int[] co, cl;
        byte[] inner;
        if (SS_TryDechunk(wire, out inner, out co, out cl)) wire = inner;

        int id; byte[] body, plain; string info;
        if (!SS_Decode(wire, isReq, out id, out body, out info, out plain)) return null;

        msgId = id;
        typeName = SS_MsgName(id);

        if (body == null || body.Length == 0)
        {
            if (SS_UI_BODY == 2) { text = "{}"; return SS_Utf8Bytes(text); }
            return new byte[0];
        }

        if (SS_UI_BODY == 2)
        {
            string js = SS_JsonBody(body, typeName);
            if (js != null && js.Length <= SS_UI_BODY_MAX) { text = js; return SS_Utf8Bytes(js); }
        }
        return body;
    }
    catch { return null; }
}

// 会话结束后把 body 换成明文，并在 Comments 写 msgId nonce key3
void SS_WritePlainBody(Session s)
{
    if (SS_STATIC_META && SS_IsStaticMeta(s)) { SS_WriteStaticBody(s); return; }
    if (!SS_IsGameSession(s)) return;

    byte[] req = null, rsp = null;
    try { req = s.requestBodyBytes; } catch { }
    try { rsp = s.responseBodyBytes; } catch { }

    if (req != null && req.Length >= 30 && !SS_LooksPlain(req))
    {
        SS_LastKey = null; SS_LastKeyName = null; SS_LastNonce = null;
        try
        {
            int id; string nm, txt;
            byte[] p = SS_PlainOf(req, true, out id, out nm, out txt);
            var lb = new System.Text.StringBuilder();
            if (p == null) { SS_LineFail(lb, true, req, s); SS_PutLine(s, true, lb.ToString()); }
            else
            {
                SS_LineInfo(lb, true, id);
                SS_PutLine(s, true, lb.ToString());
                if (SS_UI_BODY > 0 && SS_UI_BODY_REQ)
                {
                    try { s.requestBodyBytes = p; } catch { }
                }
            }
        }
        catch { }
    }

    if (rsp != null && rsp.Length >= 30 && !SS_LooksPlain(rsp))
    {
        SS_LastKey = null; SS_LastKeyName = null; SS_LastNonce = null;
        try
        {
            int id; string nm, txt;
            byte[] p = SS_PlainOf(rsp, false, out id, out nm, out txt);
            var lb = new System.Text.StringBuilder();
            if (p == null) { SS_LineFail(lb, false, rsp, s); SS_PutLine(s, false, lb.ToString()); }
            else
            {
                SS_LineInfo(lb, false, id);
                SS_PutLine(s, false, lb.ToString());
                if (SS_UI_BODY > 0 && SS_UI_BODY_RESP)
                {
                    if (txt != null) { try { s.utilSetResponseBody(txt); } catch { } }
                    try { s.responseBodyBytes = p; } catch { }
                }
            }
        }
        catch { }
    }
}

// 请求发出前处理
void OnBeforeRequest(Session oSession)
{
    SS_Handle(oSession, true);
}

// 响应到达时处理
void OnBeforeResponse(Session oSession)
{
    SS_Handle(oSession, false);
}

// 会话结束后换 body
void OnSessionCompleted(Session oSession)
{
    SS_WritePlainBody(oSession);
}

// 脚本加载时预热
void OnBoot()
{
    SS_EnsureMap();
    if (SS_MITM) { try { SS_MitmInit(); } catch { } }
}
