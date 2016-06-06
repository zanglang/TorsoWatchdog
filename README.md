# TorsoWatchdog

This is a simple watchdog program part of the 'Mufat' automated testing suite, created by Muvee Technologies Pte Ltd. The watchdog is tasked for killing unit tests that run longer than a predefined amount of time, so that machines can report a failure and quickly move on to the next unit test.

## Details

The `TorsoWatchdog` process when launched waits for Mufat's `Torso.exe` process to be started (see the TorsoSharp project). If `Torso.exe` has run for more than `x` amount of time (Default 45 minutes), it is killed and the timeout is logged.

## Usage

`TorsoWatchdog.exe <minutes>`
