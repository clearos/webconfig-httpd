# webconfig-httpd

Forked version of httpd in a chroot with ClearOS changes applied

## Update usage
  Add __#kojibuild__ to commit message to automatically build

* git clone git://github.com/clearos/webconfig-httpd.git
* cd gconsole
* git checkout c7
* git remote add upstream git://git.centos.org/rpms/httpd.git
* git pull upstream c7
* git checkout clear7
* git merge --no-commit c7
* git commit
