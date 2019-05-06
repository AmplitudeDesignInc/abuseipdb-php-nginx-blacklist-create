## Contributing

1. Fork the project.

2. Clone your fork.

3. Run "composer update" to check/download the development requirements.

4. Make your changes/updates/bugfixes.

5. Run "php vendor/bin/phpunit" to run the tests.

6. Check the phpunit coverage reports in build/coverage/

7. Run "php vendor/bin/phpcs --standard=PSR2 app/" to validate changes as PSR2. The TravisCI build will only fail on errors, not warnings.

8. Issue a pull request.
