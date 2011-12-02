//-----------------------------------------------------------------------
// <copyright file="Program.cs" company="muvee Technologies Pte Ltd">
//   Copyright (c) muvee Technologies Pte Ltd. All rights reserved.
// </copyright>
// <author>Jerry Chong</author>
//-----------------------------------------------------------------------

namespace TorsoWatchdog
{
    using System;
    using System.Diagnostics;
    using System.IO;
    using System.Threading;

    /// <summary>
    /// Utility program that monitors a running process and kills it if the
    /// process runs longer than MAX_TIMEOUT
    /// </summary>
    public class WatchDog
    {
        /// <summary>
        /// Log file to write to
        /// </summary>
        private static string LOG = @"C:\muveedebug\log.txt";

        /// <summary>
        /// Maximum stall times allowed
        /// </summary>
        private static int MAX_WAIT_COUNT = 40;

        /// <summary>
        /// Maximum milliseconds until a process is considered timed out
        /// </summary>
        private static int MAX_TIMEOUT = 2700;

        /// <summary>
        /// Main function
        /// </summary>
        /// <param name="args">Command line arguments</param>
        public static void Main(string[] args)
        {
            string name = "Torso.exe";

            // filename to search
            if (args.Length > 0)
            {
                name = args[0];
            }

            // maximum timeout
            if (args.Length > 1)
            {
                MAX_TIMEOUT = Int32.Parse(args[1].ToString()) * 60;
            }

            // main loop
            WatchDog dog = new WatchDog();
            while (true)
            {
                try
                {
                    Process p = dog.LookForProcess(name);
                    dog.WatchProcess(p);
                }
                catch (Exception e)
                {
                    Console.WriteLine("Watchdog exception: " + e);
                }
            }
        }
        
        /// <summary>
        /// Waits for and blocks until a process is found running
        /// </summary>
        /// <param name="name">Filename to search for</param>
        /// <returns>Process instance</returns>
        public Process LookForProcess(string name)
        {
            Console.WriteLine("Watching process : " + name);

            // loop until matching process is found
            Process[] processes;
            do
            {
                Console.Write("\r");
                Thread.Sleep(1000);
                processes = Process.GetProcessesByName(name);
                Console.Write("Process not available... waiting");
            }
            while (processes.Length == 0);

            Console.WriteLine("\nProcess found.. watching");
            return processes[0];
        }

        /// <summary>
        /// Monitors the process and kills it if it runs for more than MAX_TIMEOUT
        /// milliseconds, or if its memory/CPU usage appears to have stalled
        /// </summary>
        /// <param name="process">Process instance to monitor</param>
        /// <returns>Whether the Process has closed in a normal manner. Returns
        /// False if killed after timeout/stalling</returns>
        public bool WatchProcess(Process process)
        {
            int waitCount = 0;
            int waitTime = 0;
            int threadCount = 0;
            int handleCount = 0;
            long workingSet = 0;
            long pageSize = 0;
            TimeSpan privilegedProcessorTime = TimeSpan.Zero,
                totalProcessorTime = TimeSpan.Zero,
                userProcessorTime = TimeSpan.Zero;

            do
            {
                // process not running or has closed
                if (process == null || process.HasExited)
                {
                    Console.WriteLine("Exited gracefully.");
                    return true;
                }

                Console.Write("\r");
                if (process.WorkingSet64 == workingSet &&
                    process.Threads.Count == threadCount &&
                    process.HandleCount == handleCount &&
                    process.PrivilegedProcessorTime == privilegedProcessorTime &&
                    process.TotalProcessorTime == totalProcessorTime &&
                    process.UserProcessorTime == userProcessorTime &&
                    process.PagedMemorySize64 == pageSize)
                {
                    // resources used has not changed. stalled?
                    Console.Write("Watching... (stagnating) " + waitCount.ToString() + "\t");
                    waitCount++;
                }
                else
                {
                    workingSet = process.WorkingSet64;
                    threadCount = process.Threads.Count;
                    handleCount = process.HandleCount;
                    privilegedProcessorTime = process.PrivilegedProcessorTime;
                    totalProcessorTime = process.TotalProcessorTime;
                    userProcessorTime = process.UserProcessorTime;
                    pageSize = process.PagedMemorySize64;
                    Console.Write("Watching.... (active)\t");
                    waitCount = 0;
                }

                // wait 5 seconds for process to exit
                process.WaitForExit(5000);
                waitTime += 5;
            }
            while (waitCount < MAX_WAIT_COUNT && waitTime < MAX_TIMEOUT);

            // stalled or timed out
            for (int attempts = 0; attempts < 3; attempts++)
            {
                try
                {
                    using (StreamWriter writer = new StreamWriter(
                        new FileStream(LOG, FileMode.Append, FileAccess.Write)))
                    {
                        if (waitTime >= MAX_TIMEOUT)
                        {
                            writer.WriteLine(String.Format(
                                "{0}\tTorsoWatchDog.cs\tAbsolute timeout after waiting for {1} seconds",
                                DateTime.Now.ToLocalTime().ToString("yyyy-MM-dd hh:mm:ss"),
                                MAX_TIMEOUT));
                            Console.WriteLine("Absolute timeout");
                        }
                        else
                        {
                            writer.WriteLine("Stall timeout");
                            Console.WriteLine("Stall timeout");
                        }

                        // finished writing
                        break;
                    }
                }
                catch (Exception e)
                {
                    Console.WriteLine(
                        "Error opening logfile attempt #{0}: " + e,
                        attempts);
                    Thread.Sleep(5000);
                }
            }

            // kill the process
            Console.WriteLine("Killing!");
            process.Kill();
            process.WaitForExit();
            return false;
        }
    }
}
