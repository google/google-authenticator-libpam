/**
 * A Jenkinsfile existing in a project is seen by jenkins and used to build a
 * project. For documentation, see:
 * https://jenkins.io/doc/book/pipeline/jenkinsfile/. For variables that can
 * be used, see
 * https://jenkins.webscalenetworks.com/job/product/job/control/pipeline-syntax/globals.
 */

node('master') {
  /* Checks out the main source tree */
  stage('scm') {
    /* Delete the entire directory first. */
    deleteDir()
    checkout(scm)

    /* Set a version number and a component for the debian repo.
     * The version number is determined from the most recent tag. If
     * a master build is being performed, create a tag and increment
     * the webscale version number, and use a component of "main".
     * If running a branch build, append a timestamp to the most
     * recent tag and use a component of "test".
     */
    sh('git fetch --tags')
    def last_tag = sh(
      script: 'git describe --tags --abbrev=0 remotes/origin/master',
      returnStdout: true
    )
    echo('last tag is ' + last_tag)
    def m = (last_tag =~ ~/^(.+?)(?:-webscale(\d+))?$/)
    m.find()
    version = m.group(1)
    revision = (m.group(2) ?: '0').toInteger()
    component = 'main'
    /* It is necessary to set this to null, since crossing a stage
     * boundary will attempt to serialize it and it is not serializable.
     */
    m = null
    if (env.BRANCH_NAME == 'master') {
      if (sh(script: 'git rev-list -n 1 ' + last_tag, returnStdout: true)
       != sh(script: 'git rev-list -n 1 HEAD', returnStdout: true)) {
        version = version + '-webscale' + (revision + 1)
        sh('git tag ' + version + ' origin/master')
        sh('git push --tags')
      }
    } else {
      component = 'test'
      version = version + '-webscale' + revision +
        new Date().format('-yyyyMMddHHmm')
    }

    # Set the build name and description to make it easy to identify
    # from the list of jenkins jobs.
    currentBuild.displayName = version + ' from ' + env.BRANCH_NAME
    currentBuild.description = sh(
      returnStdout: true,
      script: 'git log "--pretty=format:%s (%an)" -1'
    )
  }

  /* Build the thing. These commands are taken from the instructions in
   * README.md, with a modification to install locations in order to put
   * things in locations consistent with the Ubuntu packaging of
   * libpam-google-authenticator.
   */
  stage('build') {
    sh('./bootstrap.sh')
    sh('./configure --prefix=/usr --libdir=/lib')
    sh('make')
  }

  /* Create the package. Publish it to the "public" repo, into distributions
   * trusty (14.04) and xenial (16.04). The component will have been
   * previously set to "test" or "main" to distinguish from development
   * versus production builds.
   */
  stage('package') {
    dir('product') {
      sh('cp -rp ../libpam-webscale-authenticator .')
    }
    sh('DESTDIR=' + env.WORKSPACE + '/product/libpam-webscale-authenticator ' +
      'make install')
    dir('product') {
      sh('REPO_DEBIAN=/var/www/public/debian VERSION=' + version +
        ' REPO_DISTS="trusty xenial" build-and-publish ' + component)
    }
  }
}
