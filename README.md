# depwatch

depwatch looks at the dependencies in a Python project and tells you which ones are actually worth worrying about.

## The problem

A normal project pulls in dozens or hundreds of open-source packages. You install them once and forget about them. But some are abandoned, some are maintained by a single person who has moved on, and some have known security holes. You usually only find out when something breaks. Nothing makes it easy to look at a `requirements.txt` and see where the real risk is.

## What it does

You give it a `requirements.txt`. It collects public data about every dependency — known vulnerabilities, how recently it was released, how many people maintain it, how widely it is used, and its license — and turns that into one risk score per package. Then it ranks them, so the few that need your attention sit at the top instead of being buried in a list of a hundred.

## Why this one

Most tools that do something like this either cost money or check a single repository at a time. depwatch reads your whole dependency list in one go, runs on public data, and is free.

## Status

Early development.
