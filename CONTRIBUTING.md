# Contributing to `cerebro`

We'd love for you to contribute to our source code and to make `cerebro`
even better than it is today! Here are the guidelines we'd like you to follow:

 - [Code of Conduct](#coc)
 - [Issues, Bugs and Submission Guidlines](#issue_bugs_submission)
 - [Coding Rules](#rules)

## <a name="coc"></a> Code of Conduct

Help us keep `cerebro` open and inclusive. Please be kind to and considerate
of other developers, as we all have the same goal: make `cerebro` as good as
it can be.

## <a name="issue_bugs_submission"></a> Issues, Bugs and Submission Guidelines

If you find a bug in the source code, you can
help us by submitting [an issue][issue-link].

## <a name="submit"></a> 

### Submitting an Issue
Before you submit your issue search the archive, maybe your question was already
answered.

If your issue appears to be a bug, and hasn't been reported, open a new issue.
Help us to maximize the effort we can spend fixing issues and adding new
features by not reporting duplicate issues. Providing the following information
will increase the chances of your issue being dealt with quickly:

* **Overview of the Issue** - certain secrets are not matched.
* **Motivation for or Use Case** - explain why this is a bug for you
* **`cerebro` Version(s)** - is it a regression?
* **Operating System (if relevant)** - is this a problem with all systems or
  only specific ones?
* **Reproduce the Error** - provide an isolated code snippet or an unambiguous
  set of steps.
* **Related Issues** - has a similar issue been reported before?
* **Suggest a Fix** - if you can't fix the bug yourself, perhaps you can point
  to what might be causing the problem (line of code or commit)

**If you get help, help others. Good karma rules!**

### Submitting a Pull Request
Before you submit your pull request consider the following guidelines:

* Search [GitHub][github] for an open or closed Pull Request that relates to
  your submission. You don't want to duplicate effort.
* Make your changes in a new git branch:

    ```shell
    git checkout -b my-fix-branch master
    ```

* Create your patch, **including appropriate test cases**.
* Follow our [Coding Rules](#rules).
* Run the full `cerebro` test suite (aliased by `make local-test`), and ensure
  that all tests pass.
* Commit your changes using a descriptive commit message.

    ```shell
    git commit -a
    ```
  Note: the optional commit `-a` command line option will automatically "add"
  and "rm" edited files.

* Build your changes locally to ensure all the tests pass:

    ```shell
    make local-test
    ```

* Push your branch to GitHub:

    ```shell
    git push origin my-fix-branch
    ```

In GitHub, send a pull request to `cerebro:master`.
If we suggest changes, then:

* Make the required updates.
* Re-run the `cerebro` test suite to ensure tests are still passing.
* Commit your changes to your branch (e.g. `my-fix-branch`).
* Push the changes to your GitHub repository (this will update your Pull Request).

That's it! Thank you for your contribution!

#### After your pull request is merged

After your pull request is merged, you can safely delete your branch and pull
the changes from the main (upstream) repository.

## <a name="rules"></a> Coding Rules

To ensure consistency throughout the source code, keep these rules in mind as
you are working:

* All features or bug fixes **must be tested** by one or more tests.
* All classes and methods **must be documented**.

[issue-link]: https://github.com/twilio/cerebro/issues/new
[github]: https://github.com/twilio/cerebro