﻿using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SecurityLibrary;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;

namespace SecurityPackageTest
{
    [TestClass]
    public class MonoalphabeticTest
    {
        string mainPlain = "meetmeafterthetogaparty";
        string mainCipher = "phhwphdiwhuwkhwrjdsduwb".ToUpper();
        string mainKey = "defghijklmnopqrstuvwxyzabc";


        string mainPlain1 = "abcdefghijklmnopqrstuvwxyz";
        string mainCipher1 = "isyvkjruxedzqmctplofnbwgah".ToUpper();
        string mainKey1 = "isyvkjruxedzqmctplofnbwgah";

        string mainPlain2 = "hellosecuritymonoalphabetic";
        string mainCipher2 = "ukzzcokynlxfaqcmciztuiskfxy".ToUpper();

        string newPlain = "ENGLISHASTRONOMERWILLIAMLASSELLDISCOVEREDTRITON".ToLower();
        string newCipher = "EGSDAMTUMOLHGHFELWADDAUFDUMMEDDVAMIHQELEVOLAOHG".ToUpper();
        string newKey = "UNIVERSTABCDFGHJKLMOPQWXYZ".ToLower();

        [TestMethod]
        public void MonoTestEnc1()
        {
            Monoalphabetic algorithm = new Monoalphabetic();
            string cipher = algorithm.Encrypt(mainPlain, mainKey);
            Assert.IsTrue(cipher.Equals(mainCipher, StringComparison.InvariantCultureIgnoreCase));
        }

        [TestMethod]
        public void MonoTestDec1()
        {
            Monoalphabetic algorithm = new Monoalphabetic();
            string plain = algorithm.Decrypt(mainCipher, mainKey);
            Assert.IsTrue(plain.Equals(mainPlain, StringComparison.InvariantCultureIgnoreCase));
        }

        [TestMethod]
        public void MonoTestAnalysisNaive1()
        {
            Regex regex = new Regex("d.{3}hijk.{4}p.rs.u.w.{4}b.");

            Monoalphabetic algorithm = new Monoalphabetic();
            string key = algorithm.Analyse(mainPlain, mainCipher);
            List<char> keyChar = new List<char>(key);
            Assert.AreEqual(key.Length, 26);
            Assert.AreEqual(keyChar.Distinct().Count(), 26);

            Assert.IsTrue(regex.Match(key).Success);
        }

        [TestMethod]
        public void MonoTestEnc2()
        {
            Monoalphabetic algorithm = new Monoalphabetic();
            string cipher = algorithm.Encrypt(mainPlain1, mainKey1);
            Assert.IsTrue(cipher.Equals(mainCipher1, StringComparison.InvariantCultureIgnoreCase));
        }

        [TestMethod]
        public void MonoTestDec2()
        {
            Monoalphabetic algorithm = new Monoalphabetic();
            string plain = algorithm.Decrypt(mainCipher1, mainKey1);
            Assert.IsTrue(plain.Equals(mainPlain1, StringComparison.InvariantCultureIgnoreCase));
        }

        [TestMethod]
        public void MonoTestAnalysisNaive2()
        {
            Monoalphabetic algorithm = new Monoalphabetic();
            string key = algorithm.Analyse(mainPlain1, mainCipher1);
            List<char> keyChar = new List<char>(key);
            Assert.AreEqual(key.Length, 26);
            Assert.AreEqual(keyChar.Distinct().Count(), 26);
            Assert.IsTrue(key.Equals(mainKey1, StringComparison.InvariantCultureIgnoreCase));
        }

        [TestMethod]
        public void MonoTestEnc3()
        {
            Monoalphabetic algorithm = new Monoalphabetic();
            string cipher = algorithm.Encrypt(mainPlain2, mainKey1);
            Assert.IsTrue(cipher.Equals(mainCipher2, StringComparison.InvariantCultureIgnoreCase));
        }

        [TestMethod]
        public void MonoTestDec3()
        {
            Monoalphabetic algorithm = new Monoalphabetic();
            string plain = algorithm.Decrypt(mainCipher2, mainKey1);
            Assert.IsTrue(plain.Equals(mainPlain2, StringComparison.InvariantCultureIgnoreCase));
        }

        [TestMethod]
        public void MonoTestAnalysisNaive3()
        {
            Regex regex = new Regex("isy.k.{2}ux.{2}zqmct.lofn.{3}a.");

            Monoalphabetic algorithm = new Monoalphabetic();
            string key = algorithm.Analyse(mainPlain2, mainCipher2);
            List<char> keyChar = new List<char>(key);
            Assert.AreEqual(key.Length, 26);
            Assert.AreEqual(keyChar.Distinct().Count(), 26);

            Assert.IsTrue(regex.Match(key).Success);
        }


        string largePlain = "JULYPREVIOUSMONTHNEXTMONTHMEMBERSUPDATEFIRSTSCREENEDITORIALBACKONMYSOAPBOXWHYISITTHATUSEOFTHEENGLISHLANGUAGEISGETTINGSOVERYSLOPPYHOWLONGAGOWASITWHENGRAMMARCEASEDTOBEANESSENTIALELEMENTOFWRITINGADECENTESSAYAWHILEAGOTHEREWASACAMPAIGNTODOAWAYWITHTHEABERRANTAPOSTROPHENOWITSEEMSWENEEDANEWCAMPAIGNTOCONTENDWITHTHEABERRANTHYPHENYESIKNOWTHEREISAVASTDIFFERENCEBETWEENABLACKCABDRIVERANDABLACKCABDRIVERBUTNONEOFMYREFERENCEBOOKSINVITESHYPHENATIONOFBLACKCABORDRIVERANEXTREMEEXAMPLEPERHAPSBUTIMGETTINGTIREDOFSORTINGOUTHYPHENATEDWORDSANDREPLACINGTHEHYPHENWITHACOMMAORSEMICOLONORCREATINGANEWSENTENCENOOFCOURSEIMNOTPERFECTNOONEISBUTINOTONLYABHORTHEINAPPROPRIATEUSEOFAHYPHENIALSORECOGNISEASPLITINFINITIVEWHENISEEONEITMAYBEACCEPTABLEFORTHESTARSHIPENTERPRISETOBOLDLYGOBUTIDONOTTHINKTHATLOCALORGANISATIONSSHOULDBEENCOURAGEDTOPROACTIVELYENGAGEDEPARTMENTOFWORKANDPENSIONSPRESSRELEASEIRELYONJULIETOCHECKTHEPROOFCOPYOFUPDATEBEFOREYOUSEEITANDSHEWONTLETCARELESSUSEOFGRAMMARSLIPTHROUGHOOPSISHOULDNOWSAYIUSEDTORELYONJULIEASIWROTETHATBEFORESHEHANDEDINHERNOTICENOBEFOREYOUASKIDONTTHINKITWASANYTHINGISAIDORDIDSPECIFICALLYASMANYREADERSWILLKNOWADSETPROVIDEDOFFICESPACEFORTHEADMINISTRATIONFUNCTIONSOFNAEGAWITHJULIEWORKINGFORNAEGAFORTWELVEHOURSAWEEKINTHATSPACETHATCONTRACTCAMETOANABRUPTENDINMAYANDICANNOTFINDWORKWITHINTHEADSETSETUPTOMAKEUPTHOSEMISSINGHOURSSORATHERTHANTRYTOFINDASECONDPARTTIMEJOBJULIEHASFOUNDHERSELFFULLTIMEWORKSHEWILLBEGREATLYMISSEDNOTLEASTFORHERABILITYTOSPOTANABERRANTHYPHENORAPOSTROPHECHANGESAREAFOOTWELLTHEYWOULDHAVETOBEWOULDNTTHEYDAWNYESTHEONEWHOWRITESTHEFUNNYCOMMENTSINUPDATEWILLBETAKINGOVERJULIESJOBOFTHENEWSPAPERSTHETIMINGISRIGHTASHERYOUNGESTSTARTSFULLTIMESCHOOLINSEPTEMBERRUTHWARNERWHOMMANYOFYOUALREADYKNOWASADSETSDATAMANAGERALSOINCONTROLOFTHEWEBSITEWILLBETAKINGOVERASMEMBERSHIPSECRETARYASFORHELPINTHEOFFICEIMINTERVIEWINGFOURPEOPLETOMORROWANDEXPECTTOBEABLETOAPPOINTONEOFTHEMTOSTARTONAUGUSTTHATGIVESHERTHEYAREALLFEMALETHREEWEEKSTOFINDHERFEETBEFOREIGOONHOLIDAYFORAWEEKINEVERTHOUGHTTHATIDBEBLESSINGMOBILEPHONESBUTITHINKTHATITMIGHTBENEEDEDANDTHEFAMILYWILLFORONCEHAVETOACCEPTITTHEWIDERWORLDTHELSCHASBEENTAKINGABITOFAHAMMERINGTHISMONTHWITHTHEASSOCIATIONOFCOLLEGESSTILLASSERTINGTHATTHEREARECLEARTENSIONSBETWEENTHECENTREANDTHEARMSANDINSTITUTEOFDIRECTORSSAYINGTHATTHEORGANISATIONHASMADELITTLEIFANYIMPACTONBUSINESSTHEFUNDINGOFLEARNINGANDTHEPEOPLEWHOUNDERTAKEITCONTINUESTODOMINATETHEEDUCATIONALPRESSWHILSTTHEPROVISIONOFADDITIONALMONEYUNDERTHECOMPREHENSIVESPENDINGREVIEWISWELCOMEDITSNOTENOUGHISITEVERITSEEMSTHETHEPOWERSTHATBEAREWAKINGUPTOTHEIDEATHATMAYBEJUSTMAYBEAIMINGFORAPAPERLESSSOCIETYWASNOTSUCHAGOODIDEAATLEASTNOTUNTILYOUCANBECERTAINOFBEINGABLETORETRIEVETHEINFORMATIONCREATEDWELCOMETONEWMEMBERSCAMBRIDGESHIREGRIDFORLEARNINGCONTACTLILYDAINTERTELLOGWOODMANAGEMENTCONSULTANTSLTDCONTACTVELMABENNETTTELDETAILSOFTHEWORKOFTHESETWOORGANISATIONSWILLBEPLACEDONTHEADSETWEBSITEJUSTASSOONASWEGETTHEMTOTOPOFPAGETOINDEXCIPDURGESCAUTIONONEMPLOYEERIGHTSREVIEWPATRICIAHEWITTSECRETARYOFSTATEFORTRADEANDINDUSTRYHASTODAYJULYLAUNCHEDAREVIEWOFTHEEMPLOYMENTRELATIONSACTTHEREVIEWWILLLOOKATCOMPULSORYTRADEUNIONRECOGNITIONMEASURESALTHOUGHCHANGESWILLBELIMITEDACCORDINGTOTHEDTITHECIPDEXPRESSESCAUTIONABOUTTHEINITIATIVEDIANESINCLAIRLEADPUBLICPOLICYADVISERRESPONDEDTHELAWISWORKINGWELLATTHEMOMENTANDISFINELYBALANCEDBETWEENEMPLOYERSANDEMPLOYEESFORINSTANCEMANYTRADEUNIONSARECURRENTLYWINNINGCLAIMSUNDERTHEACTWEHOPETHATTHEGOVERNMENTALLOWSTHISLEGISLATIONTOBEDDOWNBEFORECHANGESARECONSIDEREDTHEDTIHASALSOLAUNCHEDACONSULTATIONDOCUMENTTODAYONIMPLEMENTINGTHEEUDIRECTIVEONINFORMINGANDCONSULTINGSTAFFINTHEUKTHISISDUETOCOMEINTOEFFECTINTHEUKFORORGANISATIONSOFMORETHANSTAFFBYMARCHANDFORSMALLERORGANISATIONSBYMARCHORGANISATIONSEMPLOYINGLESSTHANPEOPLEARELIKELYTOBEEXCLUDEDCIPDPRESSRELEASEJULYTOTOPOFPAGETOINDEXJOHNSONHERALDSNEWERAFORBRITISHFIRMSNEWPROPOSALSTOCUTREDTAPEANDSAVESMALLBUSINESSESAROUNDMILLIONAYEARWEREUNVEILEDTODAYJULYWITHTHEPUBLICATIONOFTHEGOVERNMENTWHITEPAPERMODERNISINGCOMPANYLAWTHEWHITEPAPERREFLECTSTHECHANGESINTHEBUSINESSENVIRONMENTINRECENTYEARSPARTICULARLYTHEGROWTHOFSMALLBUSINESSESANDADVANCESINCOMMUNICATIONSTECHNOLOGYANDINCLUDESPLANSTOSIMPLIFYTHELAWANDREDUCEBURDENSONSMALLFIRMSIMPROVETRANSPARENCYTOINCREASECONFIDENCEINBUSINESSANDIMPROVEGOVERNANCETOENCOURAGEANDSUPPORTRESPONSIBLEBUSINESSOTHERKEYPROPOSALSINCLUDEDIRECTORSDUTIESWILLBESETOUTCLEARLYINSTATUTEFORTHEFIRSTTIMECORPORATEDIRECTORSWILLBEPROHIBITEDPRIVATECOMPANIESNOLONGERWILLHAVETOAPPOINTCOMPANYSECRETARIESPRIVATECOMPANIESNOLONGERWILLHAVETOHOLDAGMSUNLESSMEMBERSWANTTHEMCOMPANIESWILLBEABLETOEXPLOITTHEINTERNETANDEMAILTOMAKEDECISIONSCOMPANIESWILLHAVESIMPLERREPORTSANDACCOUNTSACCOUNTSWILLBEFILEDMOREQUICKLYWITHINSEVENMONTHSFORPRIVATECOMPANIESANDSIXMONTHSFORPUBLICCOMPANIESQUOTEDCOMPANIESWILLHAVETOPOSTREPORTSONWEBSITESBEFORETHISTHELARGESTCOMPANIESWILLPUBLISHANOPERATINGANDFINANCIALREVIEWCOMPANIESANDTHEIRDIRECTORSCONVICTEDOFFLOUTINGCOMPANYLAWCOULDBENAMEDINACENTRALREGISTERTHEWHITEPAPERISAVAILABLEONLINEATWWWDTIGOVUKCOMPANIESBILLASUMMARYOFTHEMEASURESOFPARTICULARINTERESTTOSMALLBUSINESSISALSOAVAILABLEDTIPRESSRELEASEPJULYTOTOPOFPAGETOINDEXCBIPRAISESCOMPANYLAWREFORMPLANSTHECONFEDERATIONOFBRITISHINDUSTRYCBIISBACKINGGOVERNMENTPROPOSALSTOREFORMCOMPANYLAWITISHOPEDTHATTHISWILLSIMPLIFYTHEREGIMEFORSMALLFIRMSWHILEIMPROVINGACCOUNTABILITYFORLARGEROGANISATIONSTHECBIISPRAISINGGOVERNMENTPLANSTOIMPLEMENTTHERECOMMENDATIONSOFTHECOMPANYLAWREVIEWITISHOPEDTHATTHISWILLMAKETHELAWCLEARERANDMOREEFFECTIVEHRLOOKJULYTOTOPOFPAGETOINDEXPATRICIAHEWITTANNOUNCESNEWAPPOINTMENTSTOTHESMALLBUSINESSCOUNCILSECRETARYOFSTATEFORTRADEANDINDUSTRYPATRICIAHEWITTTODAYJULYANNOUNCEDTHEFULLNEWMEMBERSHIPOFTHESMALLBUSINESSCOUNCILSBCTHEMEMBERSWORKWITHTHECHAIRMANWILLIAMSARGENTTOADVISETHEGOVERNMENTONISSUESAFFECTINGSMALLBUSINESSESTHESBCREPRESENTSAWIDERANGEOFSECTORSINCLUDINGMANUFACTURINGRETAILSOCIALENTERPRISETOURISMBUSINESSSUPPORTENVIRONMENTALBUSINESSESMEDIAANDENTERTAINMENTRECRUITMENTACCOUNTANCYANDACADEMIATHEMEMBERSHIPREPRESENTSALLPARTSOFTHEUKANDINCLUDESPEOPLEOFDIFFERENTAGESANDBACKGROUNDSDTIPRESSRELEASEPJULYUPDATECOMMENTTHEPRESSRELEASELISTSTHEPEOPLEWITHSHORTBIOGSANDSOMEOFTHEMREALLYAREFROMSMALLBUSINESSESTOTOPOFPAGETOINDEXSMALLBUSINESSSECTORGROWTHEQUIVALENTTOOVERNEWSTARTUPSEVERYDAYNIGELGRIFFITHSHAILSNETINCREASEINBUSINESSPOPULATIONNEWFIGURESPUBLISHEDTODAYJULYSHOWTHEREWASANETINCREASEOFMORETHANFIRMSOPERATINGINTHEUKINCOMPAREDTOTHEPREVIOUSYEAREQUIVALENTTOOVERNEWBUSINESSESSTARTINGUPEVERYDAYACCORDINGTONEWSTATISTICSFROMTHEDTISSMALLBUSINESSSERVICESBSTHEBUSINESSPOPULATIONTOTALLEDLASTYEARCOMPAREDTOINTHEYEAROTHERFINDINGSSHOWTHEREWEREMILLIONMOREBUSINESSESTHANINTHEFIRSTYEARFORWHICHCOMPARABLEFIGURESAREAVAILABLETHENUMBEROFMEDIUMSIZEDBUSINESSESREACHEDFORTHEFIRSTTIMEINSEVENYEARSANDATLEASTOFBUSINESSESINALLINDUSTRIESWERESMESTHEFULLSTATISTICSCANBEDOWNLOADEDFROMTHESMALLBUSINESSSERVICEWEBSITEATWWWSBSGOVUKSTATISTICSDTIPRESSRELEASEPJULYTHEGAMECOMESTIMATESTHATWORLDCUPABSENTEEISMCOSTTHEUKAROUNDMILLIONTHISFIGUREISONLYATENTHOFTHEPREDICTEDCOSTSINCEMANYEMPLOYERSWERECOOPERATIVEANDALLOWEDEMPLOYEESTOEITHERCHANGETHEIRHOURSORWATCHTHEMATCHESATWORKHOWEVEROFFANSSTILLADMITTEDTOTAKINGATLEASTONEDAYASSICKLEAVEIRSEMPLOYMENTREVIEWISSUEJULYTOTOPOFPAGETOINDEXCOMMUNICATIONSKILLSLACKINGATTHETOPACCORDINGTONEWRESEARCHFROMTHEAZIZCORPORATIONBRITAINSTOPBUSINESSLEADERSARELARGELYUNHEARDUNRECOGNISEDANDCONSIDEREDUNABLETOCOMMUNICATEEFFECTIVELYBYTHEIRBUSINESSPEERSTHERESEARCHREVEALEDTHATWHILEOFUKCOMPANYDIRECTORSCONSIDERUSBUSINESSEXECUTIVESTOHAVEANEXCELLENTORGOODMEDIAIMAGEANDREPUTATIONONLYBELIEVETHESAMEOFUKEXECUTIVESINADDITIONFEELTHATTHEMEDIAIMAGEOFTHEUKSLEADINGBUSINESSEXECUTIVESISINNEEDOFIMPROVEMENTTRAININGZONELEARNINGWIREISSUEJULYTOTOPOFPAGETOINDEXTHEHUMBLELEADERANARTICLEINBULLETPOINTJUNEISSUEARGUESTHATHAVINGALARGERTHANLIFECORPORATEHEROASALEADERCANBEDETRIMENTALTOANORGANISATIONTHEMAINCRITICISMSOFTHISTYPEOFLEADERARETHATTHEYARESELFSERVINGMOREINTERESTEDINSELFPROMOTIONANDCELEBRITYTHANTEAMWORKTHEARTICLEFURTHERSUGGESTSTHATINMANYCASESTHEYFAILTOADDVALUEDONOTDELIVERSUSTAINABLERESULTSANDDONTWORKTOIMPROVEPERFORMANCETHEARTICLETELLSUSTHATTRULYTRANSFORMATIONALLEADERSHAVEANEQUALRATIOOFHUMILITYANDPROFESSIONALWILLTHEYAREABLEMANAGERSRATHERTHANAFGUREHEADFORTHEMEDIAANDCANENGENDEREMPLOYEETRUSTCOMMITMENTANDLOYALTYTHEYWILLALSOHAVEADESIRETOSHUNPUBLICITYCHANNELAMBTIONINTODEVELOPINGTHECOMPANYNOTTHEMSELVESGIVECREDITTOOTHERSAROUNDTHEMANDDESPISEMEDIOCRITYTOTOPOFPAGETOINDEXWHATAMESSPARTICPATIONASASMPLEMANAGERIALRULETOCOMPLEXIFYORGANISATIONSACTUALLYASERIOUSRESEARCHPAPERWHICHLOOKSATSOMEOFTHESIMPLERULESOFMANAGEMENTWHCHNTHEENDCANFOULUPOURLIVESFORGOODBUTONLYIFWELETTHEMWEALLIASSUMEKNOWOFTHEHORSEMADEBYACOMMITTEEINTODAYSCONSULTATIVECLMATEWECOULDBEHEADINGFORTRYINGTODEALINCAMELSUNLESSULTIMATELYTHEMANAGERIETHESINGLEPERSONRESPONSIBLEFORMAKINGANDIMPLEMENTNGTHEDECISIONDECIDESOURHORSESSHOULDNOTHAVEHUMPSWHETHERONEORTWOISIMMATERIALSOINTHEENDWEHAVETHEAUTOCRATICDICTATORIALVICTORIANPARENTWHOSEOFFSPRINGMIGHTIFDARINGTOQUESTIONRECEIVETHERESPONSEBECAUSEISAYITISJOURNALOFMANAGEMENTSTUDIESMARCHUPDATECOMMENTONTHEOTHERHANDTHEEUROPEANDIRECTIVESAYSTHOUSHALTCONSULTANDATLENGTHUNLESSTHEREARELESSTHANSTAFFINYOURORGANISATIONSORRYGUYSTHATMEANSTHATICANCONTINUETOBETHEAUTOCRATCDCTATORIALPARENTTYPEATLEASTINLAWIFNOTREALITYTOTOPOFPAGETOINDEXLEADERSNEEDMORETRAININGAYEARAFTERTHELIBRARYWORLDSRECRUTRETANANDLEADREPORTWARNEDOFFALLINGSTANDARDSINEXECUTIVEABILITYMUSEUMSAREFACINGASIMLARLEADERSHIPCRISISSPEAKINGATTHEANNUALMUSEUMDRECTORSCONFERENCELIZAMOSOFTHECOUNCILFOREXCELLENCEINMANAGEMENTANDLEADERSHIPTOLDDELEGATESTHATTHEYSHOULDHEEDTHEDSQUETBEINGVOICEDBYJUNIORANDMIDDLEMANAGERSINTHEPUBLICSECTORACCORDNGTOARECENTREPORTOFJUNIORANDMIDDLEMANAGERSCLAIMTHATLEADERSHPNTHEIRORGANISATIONISPOORMSAMOSBELIEVESTHATTHISMATTERSBECAUSEGOODLEADERSCANNSPIREANDENERGISETHEIREMPLOYEESWHICHHASAPOSTVEEFFECTONPERFORMANCELIBRARYANDINFORMATIONUPDATEJULYVOLTOTOPOFPAGETOINDEXPATHTOTHEGATEWAYISCLEAREDAYEARAGOANENTREPRENEURSEEKINGHELPTOSETUPACOMPANYINGLASGOWRISKEDBEINGKNOCKEDDOWNINARUSHOFAGENCIESBRANDISHINGMORETHANDIFFERENTSUPPORTPRODUCTSANDSERVICESNEWBUSINESSESFACEDABEWILDERINGCHOICEOFDIFFERENTPUBLICSECTORAGENCIESPROVIDINGACCESSTOOVERBUSINESSSUPPORTPARTNERSHPSMOSTLYKNOWNBYCONFUSINGTHREELETTERACRONYMSYETDESPITETHEWELTEROFSERVICESAVAILABLEWITHLITERALLYHUNDREDSOFADVISERSGRANTSANDTRAININGSCHEMESONOFFERRESEARCHSHOWEDTHATGLASGOWURGENTLYNEEDEDTOFINDBETTERWAYSTOIMPROVEITSBUSINESSBIRTHRATEANDITSINDIGENOUSCOMPANYSURVIVALRATETHEVULNERABILITYOFSMALLANDMEDIUMSIZEDENTERPRISESSMESTOFAILURENTHEIREARLYYEARSISCLEARANDINGLASGOWONLYOFSMESSURVIVELONGERTHANTHREEYEARSCOMPAREDTOTHENATIONALTHREEYEARSURVIVALRATEOFONTOPOFLOWERTHANAVERAGESURVIVALRATESGLASGOWALSOHADAPROBLEMWITHEUROPEANBUSINESSGRANTSBEINGLEFTUNCLAIMEDBECAUSEELIGIBLECOMPANESDDNOTAPPLYFORTHECASHONOFFERDUNCANTANNAHILLCHIEFEXECUTIVEOFGLASGOWCHAMBEROFCOMMERCESEZEDTHECHANCETOPOOLTHERESOURCESOFTHEPRIVATEANDPUBLCSECTORSINAMAJOREFFORTTOADDRESSTHESHORTCOMINGSOFTHESYSTEMANDCREATEASNGLEPOINTOFENTRYFORCOMPANIESSEEKNGHELPATANYSTAGEOFTHEIRDEVELOPMENTSMALLBUSINESSGATEWAYISATVALERIEDARROCHSCOTTISHHERALDJULYMYSCHOOLDAYSWERETHEHAPPESTDAYSOFMY".ToLower();
        string largeCipher = "MXOBSUHYLRXVPRQWKQHAWPRQWKPHPEHUVXSGDWHILUVWVFUHHQHGLWRULDOEDFNRQPBVRDSERAZKBLVLWWKDWXVHRIWKHHQJOLVKODQJXDJHLVJHWWLQJVRYHUBVORSSBKRZORQJDJRZDVLWZKHQJUDPPDUFHDVHGWREHDQHVVHQWLDOHOHPHQWRIZULWLQJDGHFHQWHVVDBDZKLOHDJRWKHUHZDVDFDPSDLJQWRGRDZDBZLWKWKHDEHUUDQWDSRVWURSKHQRZLWVHHPVZHQHHGDQHZFDPSDLJQWRFRQWHQGZLWKWKHDEHUUDQWKBSKHQBHVLNQRZWKHUHLVDYDVWGLIIHUHQFHEHWZHHQDEODFNFDEGULYHUDQGDEODFNFDEGULYHUEXWQRQHRIPBUHIHUHQFHERRNVLQYLWHVKBSKHQDWLRQRIEODFNFDERUGULYHUDQHAWUHPHHADPSOHSHUKDSVEXWLPJHWWLQJWLUHGRIVRUWLQJRXWKBSKHQDWHGZRUGVDQGUHSODFLQJWKHKBSKHQZLWKDFRPPDRUVHPLFRORQRUFUHDWLQJDQHZVHQWHQFHQRRIFRXUVHLPQRWSHUIHFWQRRQHLVEXWLQRWRQOBDEKRUWKHLQDSSURSULDWHXVHRIDKBSKHQLDOVRUHFRJQLVHDVSOLWLQILQLWLYHZKHQLVHHRQHLWPDBEHDFFHSWDEOHIRUWKHVWDUVKLSHQWHUSULVHWREROGOBJREXWLGRQRWWKLQNWKDWORFDORUJDQLVDWLRQVVKRXOGEHHQFRXUDJHGWRSURDFWLYHOBHQJDJHGHSDUWPHQWRIZRUNDQGSHQVLRQVSUHVVUHOHDVHLUHOBRQMXOLHWRFKHFNWKHSURRIFRSBRIXSGDWHEHIRUHBRXVHHLWDQGVKHZRQWOHWFDUHOHVVXVHRIJUDPPDUVOLSWKURXJKRRSVLVKRXOGQRZVDBLXVHGWRUHOBRQMXOLHDVLZURWHWKDWEHIRUHVKHKDQGHGLQKHUQRWLFHQREHIRUHBRXDVNLGRQWWKLQNLWZDVDQBWKLQJLVDLGRUGLGVSHFLILFDOOBDVPDQBUHDGHUVZLOONQRZDGVHWSURYLGHGRIILFHVSDFHIRUWKHDGPLQLVWUDWLRQIXQFWLRQVRIQDHJDZLWKMXOLHZRUNLQJIRUQDHJDIRUWZHOYHKRXUVDZHHNLQWKDWVSDFHWKDWFRQWUDFWFDPHWRDQDEUXSWHQGLQPDBDQGLFDQQRWILQGZRUNZLWKLQWKHDGVHWVHWXSWRPDNHXSWKRVHPLVVLQJKRXUVVRUDWKHUWKDQWUBWRILQGDVHFRQGSDUWWLPHMREMXOLHKDVIRXQGKHUVHOIIXOOWLPHZRUNVKHZLOOEHJUHDWOBPLVVHGQRWOHDVWIRUKHUDELOLWBWRVSRWDQDEHUUDQWKBSKHQRUDSRVWURSKHFKDQJHVDUHDIRRWZHOOWKHBZRXOGKDYHWREHZRXOGQWWKHBGDZQBHVWKHRQHZKRZULWHVWKHIXQQBFRPPHQWVLQXSGDWHZLOOEHWDNLQJRYHUMXOLHVMRERIWKHQHZVSDSHUVWKHWLPLQJLVULJKWDVKHUBRXQJHVWVWDUWVIXOOWLPHVFKRROLQVHSWHPEHUUXWKZDUQHUZKRPPDQBRIBRXDOUHDGBNQRZDVDGVHWVGDWDPDQDJHUDOVRLQFRQWURORIWKHZHEVLWHZLOOEHWDNLQJRYHUDVPHPEHUVKLSVHFUHWDUBDVIRUKHOSLQWKHRIILFHLPLQWHUYLHZLQJIRXUSHRSOHWRPRUURZDQGHASHFWWREHDEOHWRDSSRLQWRQHRIWKHPWRVWDUWRQDXJXVWWKDWJLYHVKHUWKHBDUHDOOIHPDOHWKUHHZHHNVWRILQGKHUIHHWEHIRUHLJRRQKROLGDBIRUDZHHNLQHYHUWKRXJKWWKDWLGEHEOHVVLQJPRELOHSKRQHVEXWLWKLQNWKDWLWPLJKWEHQHHGHGDQGWKHIDPLOBZLOOIRURQFHKDYHWRDFFHSWLWWKHZLGHUZRUOGWKHOVFKDVEHHQWDNLQJDELWRIDKDPPHULQJWKLVPRQWKZLWKWKHDVVRFLDWLRQRIFROOHJHVVWLOODVVHUWLQJWKDWWKHUHDUHFOHDUWHQVLRQVEHWZHHQWKHFHQWUHDQGWKHDUPVDQGLQVWLWXWHRIGLUHFWRUVVDBLQJWKDWWKHRUJDQLVDWLRQKDVPDGHOLWWOHLIDQBLPSDFWRQEXVLQHVVWKHIXQGLQJRIOHDUQLQJDQGWKHSHRSOHZKRXQGHUWDNHLWFRQWLQXHVWRGRPLQDWHWKHHGXFDWLRQDOSUHVVZKLOVWWKHSURYLVLRQRIDGGLWLRQDOPRQHBXQGHUWKHFRPSUHKHQVLYHVSHQGLQJUHYLHZLVZHOFRPHGLWVQRWHQRXJKLVLWHYHULWVHHPVWKHWKHSRZHUVWKDWEHDUHZDNLQJXSWRWKHLGHDWKDWPDBEHMXVWPDBEHDLPLQJIRUDSDSHUOHVVVRFLHWBZDVQRWVXFKDJRRGLGHDDWOHDVWQRWXQWLOBRXFDQEHFHUWDLQRIEHLQJDEOHWRUHWULHYHWKHLQIRUPDWLRQFUHDWHGZHOFRPHWRQHZPHPEHUVFDPEULGJHVKLUHJULGIRUOHDUQLQJFRQWDFWOLOBGDLQWHUWHOORJZRRGPDQDJHPHQWFRQVXOWDQWVOWGFRQWDFWYHOPDEHQQHWWWHOGHWDLOVRIWKHZRUNRIWKHVHWZRRUJDQLVDWLRQVZLOOEHSODFHGRQWKHDGVHWZHEVLWHMXVWDVVRRQDVZHJHWWKHPWRWRSRISDJHWRLQGHAFLSGXUJHVFDXWLRQRQHPSORBHHULJKWVUHYLHZSDWULFLDKHZLWWVHFUHWDUBRIVWDWHIRUWUDGHDQGLQGXVWUBKDVWRGDBMXOBODXQFKHGDUHYLHZRIWKHHPSORBPHQWUHODWLRQVDFWWKHUHYLHZZLOOORRNDWFRPSXOVRUBWUDGHXQLRQUHFRJQLWLRQPHDVXUHVDOWKRXJKFKDQJHVZLOOEHOLPLWHGDFFRUGLQJWRWKHGWLWKHFLSGHASUHVVHVFDXWLRQDERXWWKHLQLWLDWLYHGLDQHVLQFODLUOHDGSXEOLFSROLFBDGYLVHUUHVSRQGHGWKHODZLVZRUNLQJZHOODWWKHPRPHQWDQGLVILQHOBEDODQFHGEHWZHHQHPSORBHUVDQGHPSORBHHVIRULQVWDQFHPDQBWUDGHXQLRQVDUHFXUUHQWOBZLQQLQJFODLPVXQGHUWKHDFWZHKRSHWKDWWKHJRYHUQPHQWDOORZVWKLVOHJLVODWLRQWREHGGRZQEHIRUHFKDQJHVDUHFRQVLGHUHGWKHGWLKDVDOVRODXQFKHGDFRQVXOWDWLRQGRFXPHQWWRGDBRQLPSOHPHQWLQJWKHHXGLUHFWLYHRQLQIRUPLQJDQGFRQVXOWLQJVWDIILQWKHXNWKLVLVGXHWRFRPHLQWRHIIHFWLQWKHXNIRURUJDQLVDWLRQVRIPRUHWKDQVWDIIEBPDUFKDQGIRUVPDOOHURUJDQLVDWLRQVEBPDUFKRUJDQLVDWLRQVHPSORBLQJOHVVWKDQSHRSOHDUHOLNHOBWREHHAFOXGHGFLSGSUHVVUHOHDVHMXOBWRWRSRISDJHWRLQGHAMRKQVRQKHUDOGVQHZHUDIRUEULWLVKILUPVQHZSURSRVDOVWRFXWUHGWDSHDQGVDYHVPDOOEXVLQHVVHVDURXQGPLOOLRQDBHDUZHUHXQYHLOHGWRGDBMXOBZLWKWKHSXEOLFDWLRQRIWKHJRYHUQPHQWZKLWHSDSHUPRGHUQLVLQJFRPSDQBODZWKHZKLWHSDSHUUHIOHFWVWKHFKDQJHVLQWKHEXVLQHVVHQYLURQPHQWLQUHFHQWBHDUVSDUWLFXODUOBWKHJURZWKRIVPDOOEXVLQHVVHVDQGDGYDQFHVLQFRPPXQLFDWLRQVWHFKQRORJBDQGLQFOXGHVSODQVWRVLPSOLIBWKHODZDQGUHGXFHEXUGHQVRQVPDOOILUPVLPSURYHWUDQVSDUHQFBWRLQFUHDVHFRQILGHQFHLQEXVLQHVVDQGLPSURYHJRYHUQDQFHWRHQFRXUDJHDQGVXSSRUWUHVSRQVLEOHEXVLQHVVRWKHUNHBSURSRVDOVLQFOXGHGLUHFWRUVGXWLHVZLOOEHVHWRXWFOHDUOBLQVWDWXWHIRUWKHILUVWWLPHFRUSRUDWHGLUHFWRUVZLOOEHSURKLELWHGSULYDWHFRPSDQLHVQRORQJHUZLOOKDYHWRDSSRLQWFRPSDQBVHFUHWDULHVSULYDWHFRPSDQLHVQRORQJHUZLOOKDYHWRKROGDJPVXQOHVVPHPEHUVZDQWWKHPFRPSDQLHVZLOOEHDEOHWRHASORLWWKHLQWHUQHWDQGHPDLOWRPDNHGHFLVLRQVFRPSDQLHVZLOOKDYHVLPSOHUUHSRUWVDQGDFFRXQWVDFFRXQWVZLOOEHILOHGPRUHTXLFNOBZLWKLQVHYHQPRQWKVIRUSULYDWHFRPSDQLHVDQGVLAPRQWKVIRUSXEOLFFRPSDQLHVTXRWHGFRPSDQLHVZLOOKDYHWRSRVWUHSRUWVRQZHEVLWHVEHIRUHWKLVWKHODUJHVWFRPSDQLHVZLOOSXEOLVKDQRSHUDWLQJDQGILQDQFLDOUHYLHZFRPSDQLHVDQGWKHLUGLUHFWRUVFRQYLFWHGRIIORXWLQJFRPSDQBODZFRXOGEHQDPHGLQDFHQWUDOUHJLVWHUWKHZKLWHSDSHULVDYDLODEOHRQOLQHDWZZZGWLJRYXNFRPSDQLHVELOODVXPPDUBRIWKHPHDVXUHVRISDUWLFXODULQWHUHVWWRVPDOOEXVLQHVVLVDOVRDYDLODEOHGWLSUHVVUHOHDVHSMXOBWRWRSRISDJHWRLQGHAFELSUDLVHVFRPSDQBODZUHIRUPSODQVWKHFRQIHGHUDWLRQRIEULWLVKLQGXVWUBFELLVEDFNLQJJRYHUQPHQWSURSRVDOVWRUHIRUPFRPSDQBODZLWLVKRSHGWKDWWKLVZLOOVLPSOLIBWKHUHJLPHIRUVPDOOILUPVZKLOHLPSURYLQJDFFRXQWDELOLWBIRUODUJHURJDQLVDWLRQVWKHFELLVSUDLVLQJJRYHUQPHQWSODQVWRLPSOHPHQWWKHUHFRPPHQGDWLRQVRIWKHFRPSDQBODZUHYLHZLWLVKRSHGWKDWWKLVZLOOPDNHWKHODZFOHDUHUDQGPRUHHIIHFWLYHKUORRNMXOBWRWRSRISDJHWRLQGHASDWULFLDKHZLWWDQQRXQFHVQHZDSSRLQWPHQWVWRWKHVPDOOEXVLQHVVFRXQFLOVHFUHWDUBRIVWDWHIRUWUDGHDQGLQGXVWUBSDWULFLDKHZLWWWRGDBMXOBDQQRXQFHGWKHIXOOQHZPHPEHUVKLSRIWKHVPDOOEXVLQHVVFRXQFLOVEFWKHPHPEHUVZRUNZLWKWKHFKDLUPDQZLOOLDPVDUJHQWWRDGYLVHWKHJRYHUQPHQWRQLVVXHVDIIHFWLQJVPDOOEXVLQHVVHVWKHVEFUHSUHVHQWVDZLGHUDQJHRIVHFWRUVLQFOXGLQJPDQXIDFWXULQJUHWDLOVRFLDOHQWHUSULVHWRXULVPEXVLQHVVVXSSRUWHQYLURQPHQWDOEXVLQHVVHVPHGLDDQGHQWHUWDLQPHQWUHFUXLWPHQWDFFRXQWDQFBDQGDFDGHPLDWKHPHPEHUVKLSUHSUHVHQWVDOOSDUWVRIWKHXNDQGLQFOXGHVSHRSOHRIGLIIHUHQWDJHVDQGEDFNJURXQGVGWLSUHVVUHOHDVHSMXOBXSGDWHFRPPHQWWKHSUHVVUHOHDVHOLVWVWKHSHRSOHZLWKVKRUWELRJVDQGVRPHRIWKHPUHDOOBDUHIURPVPDOOEXVLQHVVHVWRWRSRISDJHWRLQGHAVPDOOEXVLQHVVVHFWRUJURZWKHTXLYDOHQWWRRYHUQHZVWDUWXSVHYHUBGDBQLJHOJULIILWKVKDLOVQHWLQFUHDVHLQEXVLQHVVSRSXODWLRQQHZILJXUHVSXEOLVKHGWRGDBMXOBVKRZWKHUHZDVDQHWLQFUHDVHRIPRUHWKDQILUPVRSHUDWLQJLQWKHXNLQFRPSDUHGWRWKHSUHYLRXVBHDUHTXLYDOHQWWRRYHUQHZEXVLQHVVHVVWDUWLQJXSHYHUBGDBDFFRUGLQJWRQHZVWDWLVWLFVIURPWKHGWLVVPDOOEXVLQHVVVHUYLFHVEVWKHEXVLQHVVSRSXODWLRQWRWDOOHGODVWBHDUFRPSDUHGWRLQWKHBHDURWKHUILQGLQJVVKRZWKHUHZHUHPLOOLRQPRUHEXVLQHVVHVWKDQLQWKHILUVWBHDUIRUZKLFKFRPSDUDEOHILJXUHVDUHDYDLODEOHWKHQXPEHURIPHGLXPVLCHGEXVLQHVVHVUHDFKHGIRUWKHILUVWWLPHLQVHYHQBHDUVDQGDWOHDVWRIEXVLQHVVHVLQDOOLQGXVWULHVZHUHVPHVWKHIXOOVWDWLVWLFVFDQEHGRZQORDGHGIURPWKHVPDOOEXVLQHVVVHUYLFHZHEVLWHDWZZZVEVJRYXNVWDWLVWLFVGWLSUHVVUHOHDVHSMXOBWKHJDPHFRPHVWLPDWHVWKDWZRUOGFXSDEVHQWHHLVPFRVWWKHXNDURXQGPLOOLRQWKLVILJXUHLVRQOBDWHQWKRIWKHSUHGLFWHGFRVWVLQFHPDQBHPSORBHUVZHUHFRRSHUDWLYHDQGDOORZHGHPSORBHHVWRHLWKHUFKDQJHWKHLUKRXUVRUZDWFKWKHPDWFKHVDWZRUNKRZHYHURIIDQVVWLOODGPLWWHGWRWDNLQJDWOHDVWRQHGDBDVVLFNOHDYHLUVHPSORBPHQWUHYLHZLVVXHMXOBWRWRSRISDJHWRLQGHAFRPPXQLFDWLRQVNLOOVODFNLQJDWWKHWRSDFFRUGLQJWRQHZUHVHDUFKIURPWKHDCLCFRUSRUDWLRQEULWDLQVWRSEXVLQHVVOHDGHUVDUHODUJHOBXQKHDUGXQUHFRJQLVHGDQGFRQVLGHUHGXQDEOHWRFRPPXQLFDWHHIIHFWLYHOBEBWKHLUEXVLQHVVSHHUVWKHUHVHDUFKUHYHDOHGWKDWZKLOHRIXNFRPSDQBGLUHFWRUVFRQVLGHUXVEXVLQHVVHAHFXWLYHVWRKDYHDQHAFHOOHQWRUJRRGPHGLDLPDJHDQGUHSXWDWLRQRQOBEHOLHYHWKHVDPHRIXNHAHFXWLYHVLQDGGLWLRQIHHOWKDWWKHPHGLDLPDJHRIWKHXNVOHDGLQJEXVLQHVVHAHFXWLYHVLVLQQHHGRILPSURYHPHQWWUDLQLQJCRQHOHDUQLQJZLUHLVVXHMXOBWRWRSRISDJHWRLQGHAWKHKXPEOHOHDGHUDQDUWLFOHLQEXOOHWSRLQWMXQHLVVXHDUJXHVWKDWKDYLQJDODUJHUWKDQOLIHFRUSRUDWHKHURDVDOHDGHUFDQEHGHWULPHQWDOWRDQRUJDQLVDWLRQWKHPDLQFULWLFLVPVRIWKLVWBSHRIOHDGHUDUHWKDWWKHBDUHVHOIVHUYLQJPRUHLQWHUHVWHGLQVHOISURPRWLRQDQGFHOHEULWBWKDQWHDPZRUNWKHDUWLFOHIXUWKHUVXJJHVWVWKDWLQPDQBFDVHVWKHBIDLOWRDGGYDOXHGRQRWGHOLYHUVXVWDLQDEOHUHVXOWVDQGGRQWZRUNWRLPSURYHSHUIRUPDQFHWKHDUWLFOHWHOOVXVWKDWWUXOBWUDQVIRUPDWLRQDOOHDGHUVKDYHDQHTXDOUDWLRRIKXPLOLWBDQGSURIHVVLRQDOZLOOWKHBDUHDEOHPDQDJHUVUDWKHUWKDQDIJXUHKHDGIRUWKHPHGLDDQGFDQHQJHQGHUHPSORBHHWUXVWFRPPLWPHQWDQGORBDOWBWKHBZLOODOVRKDYHDGHVLUHWRVKXQSXEOLFLWBFKDQQHODPEWLRQLQWRGHYHORSLQJWKHFRPSDQBQRWWKHPVHOYHVJLYHFUHGLWWRRWKHUVDURXQGWKHPDQGGHVSLVHPHGLRFULWBWRWRSRISDJHWRLQGHAZKDWDPHVVSDUWLFSDWLRQDVDVPSOHPDQDJHULDOUXOHWRFRPSOHALIBRUJDQLVDWLRQVDFWXDOOBDVHULRXVUHVHDUFKSDSHUZKLFKORRNVDWVRPHRIWKHVLPSOHUXOHVRIPDQDJHPHQWZKFKQWKHHQGFDQIRXOXSRXUOLYHVIRUJRRGEXWRQOBLIZHOHWWKHPZHDOOLDVVXPHNQRZRIWKHKRUVHPDGHEBDFRPPLWWHHLQWRGDBVFRQVXOWDWLYHFOPDWHZHFRXOGEHKHDGLQJIRUWUBLQJWRGHDOLQFDPHOVXQOHVVXOWLPDWHOBWKHPDQDJHULHWKHVLQJOHSHUVRQUHVSRQVLEOHIRUPDNLQJDQGLPSOHPHQWQJWKHGHFLVLRQGHFLGHVRXUKRUVHVVKRXOGQRWKDYHKXPSVZKHWKHURQHRUWZRLVLPPDWHULDOVRLQWKHHQGZHKDYHWKHDXWRFUDWLFGLFWDWRULDOYLFWRULDQSDUHQWZKRVHRIIVSULQJPLJKWLIGDULQJWRTXHVWLRQUHFHLYHWKHUHVSRQVHEHFDXVHLVDBLWLVMRXUQDORIPDQDJHPHQWVWXGLHVPDUFKXSGDWHFRPPHQWRQWKHRWKHUKDQGWKHHXURSHDQGLUHFWLYHVDBVWKRXVKDOWFRQVXOWDQGDWOHQJWKXQOHVVWKHUHDUHOHVVWKDQVWDIILQBRXURUJDQLVDWLRQVRUUBJXBVWKDWPHDQVWKDWLFDQFRQWLQXHWREHWKHDXWRFUDWFGFWDWRULDOSDUHQWWBSHDWOHDVWLQODZLIQRWUHDOLWBWRWRSRISDJHWRLQGHAOHDGHUVQHHGPRUHWUDLQLQJDBHDUDIWHUWKHOLEUDUBZRUOGVUHFUXWUHWDQDQGOHDGUHSRUWZDUQHGRIIDOOLQJVWDQGDUGVLQHAHFXWLYHDELOLWBPXVHXPVDUHIDFLQJDVLPODUOHDGHUVKLSFULVLVVSHDNLQJDWWKHDQQXDOPXVHXPGUHFWRUVFRQIHUHQFHOLCDPRVRIWKHFRXQFLOIRUHAFHOOHQFHLQPDQDJHPHQWDQGOHDGHUVKLSWROGGHOHJDWHVWKDWWKHBVKRXOGKHHGWKHGVTXHWEHLQJYRLFHGEBMXQLRUDQGPLGGOHPDQDJHUVLQWKHSXEOLFVHFWRUDFFRUGQJWRDUHFHQWUHSRUWRIMXQLRUDQGPLGGOHPDQDJHUVFODLPWKDWOHDGHUVKSQWKHLURUJDQLVDWLRQLVSRRUPVDPRVEHOLHYHVWKDWWKLVPDWWHUVEHFDXVHJRRGOHDGHUVFDQQVSLUHDQGHQHUJLVHWKHLUHPSORBHHVZKLFKKDVDSRVWYHHIIHFWRQSHUIRUPDQFHOLEUDUBDQGLQIRUPDWLRQXSGDWHMXOBYROWRWRSRISDJHWRLQGHASDWKWRWKHJDWHZDBLVFOHDUHGDBHDUDJRDQHQWUHSUHQHXUVHHNLQJKHOSWRVHWXSDFRPSDQBLQJODVJRZULVNHGEHLQJNQRFNHGGRZQLQDUXVKRIDJHQFLHVEUDQGLVKLQJPRUHWKDQGLIIHUHQWVXSSRUWSURGXFWVDQGVHUYLFHVQHZEXVLQHVVHVIDFHGDEHZLOGHULQJFKRLFHRIGLIIHUHQWSXEOLFVHFWRUDJHQFLHVSURYLGLQJDFFHVVWRRYHUEXVLQHVVVXSSRUWSDUWQHUVKSVPRVWOBNQRZQEBFRQIXVLQJWKUHHOHWWHUDFURQBPVBHWGHVSLWHWKHZHOWHURIVHUYLFHVDYDLODEOHZLWKOLWHUDOOBKXQGUHGVRIDGYLVHUVJUDQWVDQGWUDLQLQJVFKHPHVRQRIIHUUHVHDUFKVKRZHGWKDWJODVJRZXUJHQWOBQHHGHGWRILQGEHWWHUZDBVWRLPSURYHLWVEXVLQHVVELUWKUDWHDQGLWVLQGLJHQRXVFRPSDQBVXUYLYDOUDWHWKHYXOQHUDELOLWBRIVPDOODQGPHGLXPVLCHGHQWHUSULVHVVPHVWRIDLOXUHQWKHLUHDUOBBHDUVLVFOHDUDQGLQJODVJRZRQOBRIVPHVVXUYLYHORQJHUWKDQWKUHHBHDUVFRPSDUHGWRWKHQDWLRQDOWKUHHBHDUVXUYLYDOUDWHRIRQWRSRIORZHUWKDQDYHUDJHVXUYLYDOUDWHVJODVJRZDOVRKDGDSUREOHPZLWKHXURSHDQEXVLQHVVJUDQWVEHLQJOHIWXQFODLPHGEHFDXVHHOLJLEOHFRPSDQHVGGQRWDSSOBIRUWKHFDVKRQRIIHUGXQFDQWDQQDKLOOFKLHIHAHFXWLYHRIJODVJRZFKDPEHURIFRPPHUFHVHCHGWKHFKDQFHWRSRROWKHUHVRXUFHVRIWKHSULYDWHDQGSXEOFVHFWRUVLQDPDMRUHIIRUWWRDGGUHVVWKHVKRUWFRPLQJVRIWKHVBVWHPDQGFUHDWHDVQJOHSRLQWRIHQWUBIRUFRPSDQLHVVHHNQJKHOSDWDQBVWDJHRIWKHLUGHYHORSPHQWVPDOOEXVLQHVVJDWHZDBLVDWYDOHULHGDUURFKVFRWWLVKKHUDOGMXOBPBVFKRROGDBVZHUHWKHKDSSHVWGDBVRIPB".ToUpper();
        string largeKey = "defghijklmnopqrstuvwxyzabc";

        [TestMethod]
        public void MonoTestEnc4()
        {
            Monoalphabetic algorithm = new Monoalphabetic();
            string cipher = algorithm.Encrypt(largePlain, largeKey);
            Assert.IsTrue(cipher.Equals(largeCipher, StringComparison.InvariantCultureIgnoreCase));
        }

        [TestMethod]
        public void MonoTestDec4()
        {
            Monoalphabetic algorithm = new Monoalphabetic();
            string cipher = algorithm.Decrypt(largeCipher, largeKey);
            Assert.IsTrue(cipher.Equals(largePlain, StringComparison.InvariantCultureIgnoreCase));
        }

        [TestMethod]
        public void MonoTestAnalysisFrequency()
        {
            Monoalphabetic algorithm = new Monoalphabetic();
            string plain = algorithm.AnalyseUsingCharFrequency(largeCipher);

            int count = Enumerable.Range(0, largePlain.Length)
                 .Count(i => largePlain[i] == plain[i]);

            Assert.IsTrue(count * 100 / largePlain.Length > 70);
        }

        [TestMethod]
        public void MonoTestNewEnc()
        {
            Monoalphabetic algorithm = new Monoalphabetic();
            string cipher = algorithm.Encrypt(newPlain, newKey);
            Assert.IsTrue(cipher.Equals(newCipher, StringComparison.InvariantCultureIgnoreCase));
        }

        [TestMethod]
        public void MonoTestNewDec()
        {
            Monoalphabetic algorithm = new Monoalphabetic();
            string plain = algorithm.Decrypt(newCipher, newKey);
            Assert.IsTrue(plain.Equals(newPlain, StringComparison.InvariantCultureIgnoreCase));
        }

        [TestMethod]
        public void MonoTestNewAnalysisNaive()
        {
            Regex regex = new Regex("u.ive.sta.{2}dfgh.{2}lmo.qw.{3}");

            Monoalphabetic algorithm = new Monoalphabetic();
            string key = algorithm.Analyse(newPlain, newCipher);
            List<char> keyChar = new List<char>(key);
            Assert.AreEqual(key.Length, 26);
            Assert.AreEqual(keyChar.Distinct().Count(), 26);

            Assert.IsTrue(regex.Match(key).Success);
        }
    }
}
