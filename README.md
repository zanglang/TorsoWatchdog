# TorsoWatchdog

This is a simple watchdog program part of the 'Mufat' automated testing suite, created by Muvee Technologies Pte Ltd. The watchdog is tasked for killing unit tests that run longer than a predefined amount of time, so that machines can report a failure and quickly move on to the next unit test.

## Details

The `TorsoWatchdog` process when launched waits for Mufat's `Torso.exe` process to be started (see the TorsoSharp project). If `Torso.exe` has run for more than `x` amount of time (Default 45 minutes), it is killed and the timeout is logged.

## Usage

`TorsoWatchdog.exe <minutes>`

## LICENSE

    Copyright 2016 Muvee Technologies Pte Ltd

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
