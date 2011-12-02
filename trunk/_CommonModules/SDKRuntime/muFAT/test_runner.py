from __future__ import with_statement
import hashlib, logging, os, random, re, shutil, socket, stat, subprocess
import cPickle as pickle
import xml.etree.ElementTree as etree
from datetime import datetime
from multiprocessing import Process, Queue

BASEPATH = os.path.dirname(os.path.realpath(__file__))
logger = logging.getLogger()

# globally accessible options
class Globals:
	Verbose = False
	Host = None
	Port = None
	bRetain = False
	bFindLeaks = False
	DebugBrk = False
	TestList = {}
	RetainedSamples = []
	StartTime = datetime.now()
	Daemonic = True


# relevant muFAT paths.
class muFATPaths:
	mvDebugPath = r"C:\muveeDebug"
	ResourcePath = r"Y:\mufat_resources\sdkruntime"
	ProxyPath = os.path.join(BASEPATH, r"sdkruntime\mufatProxy.dll")
	ProxyPathD = os.path.join(BASEPATH, r"sdkruntime\mufatProxyD.dll")
	TorsoExe = os.path.join(BASEPATH, r"Torso.exe")
	TorsoExeD = os.path.join(BASEPATH, r"TorsoD.exe")
	RunsPath = r"Y:\mufat\testruns\regressionPaths"
	RetainPath = r"Y:\mufat-outputs\sdkruntime\%s\RetainedSamples" % os.environ["COMPUTERNAME"]
	RunsRetainPath = os.path.join(RetainPath, Globals.StartTime.strftime("%Y%m%d%H%M%S"))
	RunsOutputPath = r"Y:\mufat-outputs\sdkruntime\%s\%s" % \
					(os.environ['COMPUTERNAME'], Globals.StartTime.strftime("%Y-%m-%d_%H_%M"))
	MediaRepo = r"C:\mufat_repo"
	NetMediaRepo = r"T:\testsets\muFAT_SDKRuntime"
	ToolsPath = r"Y:\mufat\tools"

#regular expressions 
TestResult = re.compile(r"passes:(\d+)\nfailures:(\d+)\nuntested:(\d+)", re.DOTALL | re.MULTILINE)
AssertsFailed = re.compile("^\s*([0-9\-\:\.\s]*)\s*([\-\_.\w\d\(\)]*)\s*ASSERT FAILED\s*:\s*(.*?)\n", \
									re.MULTILINE | re.DOTALL)


def getAsserts(logpath):
	"""
	@return: A tuple containing the number of assertions found in the log file,
			and second, a dictionary containing a unique set of assertions
			found.
	"""

	with open(logpath) as fp:
		# look for failed assertions
		asserts = AssertsFailed.findall(fp.read())
	uniques = {}
	for k in asserts:
		# generate a SHA1 hash of the assertion error to check for duplicates
		key = hashlib.sha1(k[1] + k[2]).hexdigest()
		count = uniques.has_key(key) and (uniques[key]["occurances"] + 1) or 1
		uniques[key] = { "file": k[1], "message": k[2] , "occurances": count }

	return len(asserts), uniques


def copy_run_media(run_path):
	"""
	Calculates a list of media files missing in the local resource folder, and
	copies it from the remote network folder.
	"""

	# media to be copied to local drive (key) from remote dir (value)
	media_map = {}
	# temporary list of parsed config files
	parsed = set()

	def loadXML(filename):
		"""Parse a muFAT XML file"""
		repo_re = re.compile(re.escape(muFATPaths.MediaRepo), re.IGNORECASE)
		media_re = re.compile('"(%s.*)"' % re.escape(muFATPaths.MediaRepo), re.IGNORECASE)
		resource_re = re.compile('"(%s.*)"' % re.escape(muFATPaths.ResourcePath), re.IGNORECASE)
		#logger.info("Evaluating " + filename)

		# check if file has already been read, or still doesn't exist
		if filename in parsed or not os.path.exists(filename):
			return

		with open(filename) as fp:
			cfg = fp.read().replace("&amp;", "&") \
					.replace("&gt;", ">") \
					.replace("&lt;", "<") \
					.replace("&#37;", "%")
			for path in resource_re.findall(cfg):
				loadXML(path)
			for path in media_re.findall(cfg):
				media_map.setdefault(path, repo_re.sub(
						muFATPaths.NetMediaRepo.replace("\\", "\\\\"), path))

		# add to parsed list so we can skip this file next time
		parsed.add(filename)

	def evaluate(filename):
		"""Recursively scans a muFAT .run file for media"""
		include_re = re.compile(r"\s*;\s*include\s*::\s*(.*)")
		#logger.info("Evaluating " + filename)

		try:
			with open(filename) as f:
				for line in f.readlines():
					line = line.strip()
					# is this a commented directive line?
					if include_re.match(line):
						newfile = include_re.findall(line)[0]
						if not os.path.isfile(newfile):
							newfile = os.path.join(os.path.dirname(run_path), newfile)
						evaluate(newfile)
						continue

					directives = line.split(",")
					if not len(directives) == 3:
						continue
					folder, config, num = directives #@UnusedVariable
					if not os.path.isfile(config):
						config = os.path.join(muFATPaths.ResourcePath, folder, config)
					# search for media and resources in config file
					loadXML(config)
		except:
			logger.error("Cannot parse " + filename, exc_info=True)

	# load all media from the config file
	evaluate(run_path)
	#logger.info("Found %d media items." % len(media_map.keys()))

	for dest, source in media_map.iteritems():
		# exists and with same file size
		if os.path.exists(dest) and \
			os.stat(source).st_size == os.stat(dest).st_size:
			continue
		else:
			# not exists or file size has changed
			if not os.path.exists(os.path.dirname(dest)):
				os.makedirs(os.path.dirname(dest))
			logger.info("Copying %s -> %s", source, dest)
			shutil.copy(source, dest)


def pickle_over_network(obj):
	"""
	used to send the report dictionary back to the host machine 
	that is collecting the data for a gridified run.
	"""
	client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	client.connect((Globals.Host, int(Globals.Port)))
	client.send(pickle.dumps(obj) + "(EOM)")
	client.close()


def create_directories():
	"""
	creates the relevant output directories for test run outputs
	"""
	for d in [muFATPaths.RunsRetainPath,
				muFATPaths.mvDebugPath,
				muFATPaths.MediaRepo,
				os.path.join(muFATPaths.RunsOutputPath, "muveedebug"),
				os.path.join(muFATPaths.RunsOutputPath, "logs")]:
		if not os.path.isdir(d):
			# logger.info("Creating: " + d)
			os.makedirs(d)


def clean_muvee_folders():
	"""
	remove all muvee specific temporary folders here.
	"""

	print "Cleaning up muvee folders..."
	for d in [os.path.join(os.getenv("ALLUSERSPROFILE"), "application data", "muvee Technologies", "071203"),
					os.path.join(os.getenv("APPDATA"), "muvee Technologies")]:
		if os.path.isdir(d):
			print "Deleting", d
			shutil.rmtree(d)

	EXCLUSION = ["install.txt", ]
	for root, dirs, files in os.walk(muFATPaths.mvDebugPath): #@UnusedVariable
		for f in files:
			if f.lower() in EXCLUSION:
				continue
			print "Deleting", os.path.join(root, f)
			os.remove(os.path.join(root, f))

	os.system("del *.html /q")
	os.system("del *.pkl /q")
	os.system("del *.txt /q")


def generate_mvrt():
	"""
	Generates a MVRT.ini containing specific tweaks/configuration for MES
	"""
	def FindPerformanceXML():
		# find mvPerformance.xml location from hklm2.xml directive
		hklm = os.path.join(os.getenv("PROGRAMFILES(X86)", os.getenv("PROGRAMFILES")),
				"muvee Technologies", "muvee Reveal", "hklm2.xml")
		if os.path.exists(hklm):
			perf = etree.parse(hklm).find("HKEY_LOCAL_MACHINE/PerformanceXMLPath")
			if perf is not None:
				return perf.get("value")
			else:
				logger.debug(hklm + " does not contain PerformanceXMLPath directive")

		# try to look under known path
		perf = os.path.join(os.getenv("ProgramData",
				os.path.join(os.getenv("ALLUSERSPROFILE"), "Application Data")),
				"muvee Technologies", "071203", "00000010", "mvProgress.xml")
		if os.path.exists(perf):
			return perf

	perf = FindPerformanceXML()
	if not perf:
		logger.debug("Cannot find mvPerformance.xml, assuming not run.")
		return False

	mvrt = os.path.join(os.getenv("COMMONPROGRAMFILES(X86)", os.getenv("COMMONPROGRAMFILES")),
							"muvee Technologies", "071203", "MVRT.ini")

	# check file permissions
	if os.path.exists(mvrt) and not os.stat(mvrt)[0] & stat.S_IWRITE:
		mvrt = os.path.join(muFATPaths.MediaRepo, "MVRT.ini")

	# XML parser
	if os.path.exists(mvrt):
		tree = etree.ElementTree(file=mvrt)
	else:
		tree = etree.ElementTree(etree.Element("mvrtini"))

	# parse mvPerformance XML results
	for param in etree.parse(perf).findall("param"):
		name = param.find("name").text
		category = param.find("category").text
		val = param.find("options").get("current")

		# create elements if not exist
		_category = tree.find(category)
		if _category is None:
			_category = etree.SubElement(tree.getroot(), category)

		_val = _category.find(name)
		if _val is None:
			_val = etree.SubElement(_category, name)
		_val.text = val

	tree.write(mvrt)
	logger.debug("Generated MVRT.ini at " + mvrt)


def run_wrapper(runstring, q, cwd=None):
	"""
	Wrapper function that launches the Torso, and which is spawned by the
	multiprocessing library's Process class.
	
	@param q: A thread-safe queue to return Torso's results back to calling
			process.
	"""
	proc = subprocess.Popen(runstring, stdout=subprocess.PIPE,
						stderr=subprocess.PIPE, cwd=cwd)
	try:
		# read standard out and err
		sout, serr = proc.communicate()
	except KeyboardInterrupt:
		print "Interrupted."
		# Ctrl-C received, still try to salvage any text from the pipe
		sout, serr = proc.communicate()

	# put the results into the queue, to wake up the blocked test_runner
	q.put([proc.returncode, sout, serr])


def runtest(runpath):
	"""
	Sets up and performs a muFAT test
	"""

	logger.info("running " + runpath)
	if os.path.isfile(runpath):
		runpath = os.path.realpath(runpath)
	shortname = os.path.basename(runpath)
	runname = os.path.splitext(shortname)[0]

	copy_run_media(os.path.join(muFATPaths.RunsPath, runpath))

	# handle debug mode
	torso = os.path.isfile(muFATPaths.TorsoExeD) and \
					muFATPaths.TorsoExeD or muFATPaths.TorsoExe
	proxy = os.path.isfile(muFATPaths.ProxyPathD) and \
					muFATPaths.ProxyPathD or muFATPaths.ProxyPath
	if not os.path.isfile(torso) or not os.path.isfile(proxy):
		raise Exception("Error: missing Torso.exe or muFAT proxy DLLs")

	def touch(filename, default_text=None):
		with open(filename, 'w') as fp:
			fp.write(default_text or "")

	create_directories()
	touch(os.path.join(muFATPaths.mvDebugPath, "SuppressAssertDialog.txt"))

	timelinename = ""
	start_time = datetime.now()
	timestamp = start_time.strftime("%Y%m%d%H%M%S")

	# runtypes
	is_rawperf = shortname.lower().find("rawperformance") >= 0
	is_timeline = shortname.lower().find("constructor") >= 0
	is_elecard = shortname.lower().find("elecard") >= 0

	# to test just raw performance, create a file called EnableEncodingPerformanceFileDump.txt  in c:\muveedebug
	if is_rawperf:
		touch(os.path.join(muFATPaths.mvDebugPath, "EnableEncodingPerformanceFileDump.txt"))

	elif is_timeline:
		touch(os.path.join(muFATPaths.mvDebugPath, "timeline.scm"))
		timelinename = os.path.join(muFATPaths.mvDebugPath, "(%s)%s_timeline.scm" % (timestamp, runname))

	elif is_elecard:
		touch(os.path.join(muFATPaths.mvDebugPath, "DisableMC.txt"))

	# set mes hard debugging on
	touch(os.path.join(muFATPaths.mvDebugPath, "mesharddebug.txt"), "on")

	# set muSE message handler.
	touch(os.path.join(muFATPaths.mvDebugPath, "OnMuseMessage.txt"), "cancel\n")

	# start debug view if possible.
	debuglog = os.path.join(muFATPaths.mvDebugPath, "debugoutputlog_%s.log" % shortname)
	if Globals.bFindLeaks and os.path.isfile(debuglog):
		dbgview = subprocess.Popen("y:\\mufat\\tools\\dbgview /f /t /l \"%s\"" % debuglog)

	execString = r"""%s /c "%s" /res %s /proxypath %s /s""" % (torso, \
					os.path.join(muFATPaths.RunsPath, runpath),
					muFATPaths.ResourcePath, proxy)

	if Globals.DebugBrk:
		execString += " /debugbrk"

	###########################################
	# Start executing test by launching Torso

	q = Queue()
	if Globals.Daemonic:
		proc = Process(target=run_wrapper, args=(execString, q,
							os.path.join(muFATPaths.RunsOutputPath, "logs")))
		proc.start()
	else:
		proc = None
		run_wrapper(execString, q, os.path.join(muFATPaths.RunsOutputPath, "logs"))
	try:
		returncode, sout, serr = q.get()
		if Globals.Verbose:
			logger.debug("%s\n%s", sout, serr)
		if proc:
			proc.join(timeout=10800) # 3 hours before killed by TorsoWatchdog
	except:
		if proc and proc.is_alive():
			proc.terminate()
		logger.debug("Terminated.", exc_info=True)
		returncode = -1

	############################################
	# Test ended or terminated

	leaks = []
	if Globals.bFindLeaks and os.path.isfile(debuglog):
		dbgview.terminate()
		dbgview.wait()
		# find leaks.
		with open(debuglog) as fp:
			leaks = re.compile("(.*?)\s({\d+})\s(.*?)normal block at (.*?), (\d+) bytes long.\n", re.DOTALL | re.MULTILINE) \
				.findall(fp.read())

	retainedSamples = [os.path.join(muFATPaths.RunsRetainPath, f) \
			for f in os.listdir(muFATPaths.mvDebugPath) \
			if f.find(runname) >= 0 \
			and os.path.splitext(f)[1] not in [".txt", ".scm", ".log"] \
			and True in [s.find(runname) >= 0 for s in Globals.RetainedSamples]]

	if is_rawperf:
		os.remove(os.path.join(muFATPaths.mvDebugPath, "EnableEncodingPerformanceFileDump.txt"))

	timeline_scm = os.path.join(muFATPaths.mvDebugPath, "timeline.scm")
	if is_timeline and os.path.isfile(timeline_scm):
		shutil.move(timeline_scm, timelinename)

	if is_elecard:
		os.remove(os.path.join(muFATPaths.mvDebugPath, "DisableMC.txt"))

	try:
		logfile = os.path.join(muFATPaths.RunsOutputPath, "logs", runname + ".txt")
		with open(logfile) as fp:
			numPass, numFail, numUntested = map(lambda x: int(x), \
											TestResult.findall(fp.read())[0])
	except:
		logger.warning("Crashed!")
		numPass, numFail, numUntested = (0, 0, 0)

	crash = (numPass, numFail, numUntested) == (0, 0, 0)
	shutdown = True

	logfile = os.path.join(muFATPaths.mvDebugPath, crash and \
					"Log.txt" or runname + "_Log.txt")
	if os.path.isfile(logfile):
		_logfile = os.path.join(muFATPaths.mvDebugPath, \
				"(%s)%s_Log.txt" % (timestamp, runname))
		shutil.move(logfile, _logfile)
		logfile = _logfile
		with open(logfile) as fp:
			is_timeout = fp.read().find("TorsoWatchDog") >= 0
		numAssertFailures, uniqueAssertDict = getAsserts(logfile)
		shutil.move(logfile, os.path.join(muFATPaths.RunsOutputPath,
				"muveedebug", os.path.basename(logfile)))
	else:
		is_timeout = False
		numAssertFailures = 0
		uniqueAssertDict = {}

	logger.info("passes:%s\tfail:%s\tuntested:%s,asserts failed:%d,leaks:%d",
				numPass, numFail, numUntested, numAssertFailures, len(leaks))

	if not crash and returncode != 0:
		shutdown = False

	minutes, seconds = divmod((datetime.now() - start_time).seconds, 60)
	hours, minutes = divmod(minutes, 60)

	results = {
		"pass": numPass,
		"fail": numFail,
		"untested": numUntested,
		"assert": numAssertFailures,
		"log": os.path.join(muFATPaths.RunsOutputPath, "muveedebug", os.path.basename(logfile)),
		"summary": os.path.join(muFATPaths.RunsOutputPath, "logs", runname + ".txt"),
		"time": (hours, minutes, seconds),
		"shutdown": shutdown,
		"crash": crash,
		"retained_samples": retainedSamples,
		"return_code": returncode,
		"timeout": is_timeout,
		"unique_asserts": uniqueAssertDict
	}

	if os.path.isfile(debuglog):
		results["debug_output"] = os.path.join(muFATPaths.RunsOutputPath,
										"muveedebug", os.path.basename(debuglog))
	if is_rawperf:
		results["perflog"] = os.path.join(muFATPaths.RunsOutputPath,
										"muveedebug", "testoutput_" + runname + ".raw.txt")
	if is_timeline:
		results["is_timeline"] = os.path.join(muFATPaths.RunsOutputPath, "muveedebug", os.path.split(timelinename)[1])
	if Globals.bFindLeaks:
		results["leak_num"] = len(leaks),
		results["leak_bytes"] = sum([int(k[4]) for k in leaks]) if leaks else 0

	# rename MES debugging files to be archived
	for f in ["FThread.Preview.txt", "FThread.Save.txt", "MESFoundation.txt"]:
		old = os.path.join(muFATPaths.mvDebugPath, f)
		new = os.path.join(muFATPaths.RunsOutputPath, "muveedebug",
						"(%s)%s_%s" % (timestamp, runname, f))
		if os.path.isfile(old):
			shutil.move(old, new)
			results[f] = new

	# move everything to the retain path
	retainables = [os.path.splitext(os.path.basename(f))[0] for f in Globals.RetainedSamples]
	for f in os.listdir(muFATPaths.mvDebugPath):
		fn = os.path.join(muFATPaths.mvDebugPath, f)

		if not os.path.isfile(fn):
			continue

		# preserve text logs and scm files
		elif os.path.splitext(f)[1] in [".txt", ".log", ".scm"]:
			shutil.move(fn, os.path.join(muFATPaths.RunsOutputPath, "muveedebug", f))

		# preserve produced samples
		elif Globals.bRetain and True in [f.find(j) >= 0 for j in retainables]:
			shutil.move(fn, os.path.join(muFATPaths.RunsRetainPath, f))

	# purge the rest of the files left
	shutil.rmtree(muFATPaths.mvDebugPath, ignore_errors=True)

	return results


def get_runs_from_dir(folder, ref=None):
	"""
	If a directory is specified as a suite, pull out all relevant .run files
	from the directory. Runs under the 'include/ignore/includes' folder are
	ignored.
	"""
	runs = []
	ignored = set(["include", "ignore", "includes"])
	for root, dirs, files in os.walk(folder): #@UnusedVariable
		for f in files:
			# path mismatch
			if os.path.splitext(f)[1] != ".run" or \
					set(root.lower().split(os.path.sep)).intersection(ignored):
				continue
			run = os.path.join(root, f)
			if ref:
				run = run.replace(ref, "")
				if run.startswith("/") or run.startswith("\\"):
					run = run[1:]
			runs.append(run)

	return runs


def parse_config(xml):
	"""Load configuration from XML file"""

	for suite in etree.parse(xml).findall("suite"):
		name = suite.get("name")
		if suite.get("enabled") == "false":
			continue

		Globals.TestList[name] = []
		# load runs from directory
		if suite.attrib.has_key("directory"):
			runs = get_runs_from_dir(os.path.join(muFATPaths.RunsPath,
												suite.get("directory")))
			Globals.TestList[name] = runs
			# samples from this suite should be retained 
			if suite.get("retain_samples") == "true":
				Globals.RetainedSamples.extend(runs)

		retainAll = suite.get("retain_samples") == "true"
		for run in suite.findall("run"):
			if run.get("enabled") == "false":
				continue
			Globals.TestList[name].append(run.get("name"))
			if run.get("retain_samples") == "true" or retainAll:
				Globals.RetainedSamples.append(run.get("name"))


def copytree2(src, dst):
	names = os.listdir(src)
	if not os.path.exists(dst):
		os.makedirs(dst)
	errors = []
	for name in names:
		srcname = os.path.join(src, name)
		dstname = os.path.join(dst, name)
		try:
			if os.path.isdir(srcname):
				copytree2(srcname, dstname)
			elif not (os.path.exists(dstname) and \
					os.stat(srcname).st_size == os.stat(dstname).st_size):
				shutil.copy2(srcname, dstname)
				logger.info("Copied " + dstname)
		except (IOError, os.error), why:
			errors.append((srcname, dstname, str(why)))
		except shutil.Error, err:
			errors.extend(err.args[0])
	try:
		shutil.copystat(src, dst)
	except OSError, why:
		if WindowsError is not None and isinstance(why, WindowsError):
			pass
		else:
			errors.extend((src, dst, str(why)))
	if errors:
		raise shutil.Error, errors


def test_runner():
	"""Main function"""

	import optparse
	p = optparse.OptionParser()
	p.add_option("--suites")
	p.add_option("--cleanup", action="store_true", \
			help="specify to ensure app data/debug files are purged before the run")
	p.add_option("--verbose", action="store_true")
	p.add_option("--host")
	p.add_option("--retain", action="store_true", help="retains test outputs to y: drive")
	p.add_option("--silent", action="store_true", help="silences console output")
	p.add_option("--show-suites", action="store_true", help="show contents of all available suites")
	p.add_option("--list-suites", action="store_true", help="list all available suites")
	p.add_option("--dry-run", action="store_true", help="dry run only, mainly to test the flow")
	p.add_option("--find-leaks", action="store_true", help="enable memory leak detection")
	p.add_option("--debug-brk", action="store_true", help="do debug break at start of each run")
	p.add_option("--pick-one", action="store_true", help="Pick only one run from each suite")
	options, runs = p.parse_args()

	Globals.bRetain = options.retain is not None
	Globals.bFindLeaks = options.find_leaks is not None
	Globals.Verbose = options.verbose is not None
	Globals.DebugBrk = options.debug_brk is not None

	parse_config("runconfig.xml")

	# reduce logging levels to be less verbose
	if options.silent:
		logger.setLevel(logging.WARN)

	# just list suites/runs available and quit
	if options.show_suites or options.list_suites:
		suites = Globals.TestList.keys()
		suites.sort()
		for suite in suites:
			logger.info("suite: " + suite)
			if options.list_suites:
				for run in Globals.TestList[suite]:
					logger.info("\trun: " + run)
				raw_input("press any key to continue")
		return

	# User specified suites to run
	suites = []
	if options.suites:
		suites = options.suites.split(",")
		if not set(suites).issubset(set(Globals.TestList.keys())):
			logger.error("The following suites are undefined: " + \
						str(set(suites).difference(set(Globals.TestList.keys()))))
			p.exit(2)

	if not suites and not runs:
		logger.error("No suites or no runs defined!")
		p.exit(2)

	# host/port specified for sending pickled results
	if options.host:
		try:
			Globals.Host, Globals.Port = options.host.split(":")
		except:
			logger.error("Host string should be in the format host:port")
			p.exit(2)

	# delete application data and debug folders
	if options.cleanup:
		clean_muvee_folders()

	create_directories()
	generate_mvrt()
	results = {}
	picklefile = open(Globals.StartTime.strftime("%Y-%m-%d_%H_%M") + ".pkl", "wb")

	# iterate through specified runs
	if len(runs) > 0:
		results["None"] = {}
		for run in runs:
			results["None"][run] = runtest(run)
			pickle.dump(results, picklefile)
	else:
		# iterate through suites
		if not suites:
			suites = Globals.TestList.keys()
		for suite, _runs in filter(lambda x: x[0] in suites, Globals.TestList.iteritems()):
			if not results.has_key(suite):
				results[suite] = {}
			# pick a random run from the suite
			if options.pick_one:
				_runs = random.sample(_runs, 1)
			for run in _runs:
				results[suite][run] = runtest(run)
				# write results after each test to a pickle file, so that if
				# we cancel the test the results are still recoverable.
				pickle.dump(results, picklefile)

	# finished running, preparing to upload results
	picklefile.close()

	# send results to a remote server
	if Globals.Host:
		pickle_over_network(results)

	# copy log files to archive folder
	for f in os.listdir(""):
		if os.path.splitext(f)[1] in [".txt", ".pkl", ".log"]:
			shutil.copy(f, os.path.join(muFATPaths.RunsOutputPath, "logs", f))

	if Globals.bRetain:
		logger.info("Cleaning up old folders in " + muFATPaths.RetainPath)
		dirs = filter(os.path.isdir,
					map(lambda d: os.path.join(muFATPaths.RetainPath, d),
						os.listdir(muFATPaths.RetainPath)))
		dirs.sort(reverse=True)
		# only need to retain up to 4 past runs
		for d in dirs[4:]:
			shutil.rmtree(os.path.join(muFATPaths.RetainPath, d))


if __name__ == "__main__":
	# logging
	logging.basicConfig(
					filename=os.path.join(os.curdir, "output.log"),
					level=logging.DEBUG,
					format="%(asctime)s %(levelname)s %(message)s")
	console = logging.StreamHandler()
	console.setLevel(logging.DEBUG)
	logger.addHandler(console)

	logger.info("****************")
	logger.info("muFAT testRunner")
	logger.info("****************")
	try:
		test_runner()
	except SystemExit:
		pass
	except:
		logger.fatal("Oh noes!", exc_info=True)
