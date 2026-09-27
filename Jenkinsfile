properties(
    [
        githubProjectProperty(
            displayName: 'loopdns.de',
            projectUrlStr: 'https://github.com/ruepp-jenkins/loopdns.de'
        ),
        // Every agent's tags derive from the same datestamp. Concurrent builds of the same branch
        // would write the same intermediate tags, and the manifest could pick up half of one build
        // and half of another.
        disableConcurrentBuilds(abortPrevious: true)
    ]
)

// `checkout scm` rather than a `git` step with a URL and a credentials id spelled out here.
//
// Two reasons. The job already knows both — it found this file by cloning the repository — so
// repeating them is a second copy that can disagree with the first. And `scm` carries the exact
// revision that produced this Jenkinsfile, so both architecture agents check out the same commit
// even if the branch moves in between — which matters now that two agents check out independently
// instead of one.
def checkoutRepo() {
    checkout scm
    sh 'chmod +x scripts/*.sh'
}

// One architecture, built natively on its own agent. The caller checks the repository out, not this
// function. The post blocks below cannot move here — junit and cleanWs are stage directives, not
// steps.
def buildImage(String arch, String platform) {
    withEnv(["EXPECTED_PLATFORM=${platform}", "TEST_REPORT_SUFFIX=${arch}"]) {
        // Two attempts, a minute apart, because what fails here is usually not the build. A Jenkins
        // restart during `docker buildx build` kills the session to buildkitd ("received prior
        // goaway ... graceful_stop") and takes the shared builder with it; a registry push can meet
        // a transient 5xx. Running start.sh again answers both, because it is idempotent:
        // docker_initialize.sh recreates a builder it no longer finds, BuildKit replays the test
        // stage from cache, and pushing the same content by digest twice is a no-op. The minute is
        // for the restart case, where the node has only just reconnected and its Docker daemon may
        // still be coming up.
        //
        // A red test suite is retried too, and that is affordable: the cached test stage replays and
        // the Dockerfile's `verified` stage refuses again within seconds. An aborted build is not
        // retried at all — `retry` rethrows the interruption rather than looping, so this does not
        // fight the abortPrevious above.
        def attempt = 0
        retry(2) {
            attempt++
            if (attempt > 1) {
                echo "Build (${arch}) failed; retrying once in 60s"
                sleep time: 60, unit: 'SECONDS'
            }

            // Bound here rather than in the pipeline's environment block, which would export the
            // registry password into every sh step on every agent — the cleanup and the test suite
            // included, neither of which log in. This is the only step in this function that does:
            // start.sh calls scripts/docker_initialize.sh.
            withCredentials([string(credentialsId: 'DOCKER_API_PASSWORD',
                                    variable: 'DOCKER_API_PASSWORD')]) {
                sh './scripts/start.sh'
            }
        }

        // The image was pushed without a tag, so its digest is the only handle on it — and it is on
        // the wrong machine. stash is the one channel declarative pipelines offer between agents. It
        // has to happen here in steps: the post block below wipes the workspace.
        stash name: "digest-${arch}", includes: "digest-${arch}.txt"
    }
}

def publishManifest() {
    unstash 'digest-amd64'
    unstash 'digest-arm64'
    // The second and last place that logs in — see buildImage for why the binding is here.
    withCredentials([string(credentialsId: 'DOCKER_API_PASSWORD',
                            variable: 'DOCKER_API_PASSWORD')]) {
        sh './scripts/docker_manifest.sh'
    }
}

pipeline {
    // No global agent: the whole point of this pipeline is that the architecture builds run on
    // different machines, so every stage names its own.
    agent none

    environment {
        IMAGE_FULLNAME = 'ruepp/loopdns'

        // Every agent builds its own architecture and nothing else. 'host' is what tells
        // scripts/docker_platforms.sh to skip the QEMU registration: with a machine per platform
        // there is nothing left to emulate, and the --privileged binfmt container is no longer
        // needed on either agent.
        DOCKER_PLATFORMS = 'host'

        // The architectures scripts/docker_manifest.sh joins into one manifest list.
        MANIFEST_ARCHS = 'amd64 arm64'
    }

    triggers {
        URLTrigger(
            cronTabSpec: 'H/30 * * * *',
            labelRestriction: 'urltrigger',
            entries: [
                URLTriggerEntry(
                    url: 'https://mcr.microsoft.com/v2/dotnet/sdk/manifests/10.0',
                    contentTypes: [
                        JsonContent(
                            [
                                JsonContentEntry(jsonPath: '$.protected')
                            ]
                        )
                    ]
                ),
                URLTriggerEntry(
                    url: 'https://mcr.microsoft.com/v2/dotnet/aspnet/manifests/10.0',
                    contentTypes: [
                        JsonContent(
                            [
                                JsonContentEntry(jsonPath: '$.protected')
                            ]
                        )
                    ]
                )
            ]
        )
    }

    stages {
        stage('Prepare') {
            // The datestamp goes into every tag, including the one the manifest step below looks
            // up. Computed once here rather than by each agent: two machines running `date` disagree
            // across midnight and across time zones, and the manifest would then reference a tag
            // that was never written.
            agent { label 'docker' }
            steps {
                checkoutRepo()
                script {
                    env.DATESTAMP = sh(script: 'date +%Y%m%d', returnStdout: true).trim()
                }
                echo "Tag base for this build: ${env.DATESTAMP}"
            }
            post {
                always {
                    cleanWs()
                }
            }
        }

        stage('Build') {
            // Parallel across architectures. Each agent builds and pushes its own architecture by
            // digest; the manifest step below joins the two into one multi-arch tag.
            parallel {
                stage('amd64') {
                    agent { label 'docker' }
                    steps {
                        checkoutRepo()
                        buildImage('amd64', 'linux/amd64')
                    }
                    post {
                        always {
                            // 'always', so the report is published even when the build fails — which
                            // is precisely when knowing which test broke is worth something.
                            // allowEmptyResults stays false on purpose: a missing report means the
                            // tests did not run, and that should fail loudly rather than pass quietly.
                            junit testResults: 'test-results/*.junit.xml',
                                  allowEmptyResults: false,
                                  keepProperties: true
                            sh './scripts/docker_cleanup.sh'
                            cleanWs()
                        }
                    }
                }
                stage('arm64') {
                    agent { label 'oracle_docker' }
                    steps {
                        checkoutRepo()
                        buildImage('arm64', 'linux/arm64')
                    }
                    post {
                        always {
                            junit testResults: 'test-results/*.junit.xml',
                                  allowEmptyResults: false,
                                  keepProperties: true
                            sh './scripts/docker_cleanup.sh'
                            cleanWs()
                        }
                    }
                }
            }
        }

        stage('Manifest') {
            // Reached only when both architectures pushed: a failed branch fails the parallel stage
            // and this never runs, so a broken build cannot end up as a published tag that silently
            // serves one architecture.
            agent { label 'docker' }
            steps {
                checkoutRepo()
                publishManifest()
            }
            post {
                always {
                    cleanWs()
                }
            }
        }
    }

    post {
        always {
            // No cleanWs here: with `agent none` this block has no workspace to clean, and asking
            // for one fails the build after everything already succeeded. Each stage cleans its own.
            discordSend result: currentBuild.currentResult,
                description: env.GIT_URL,
                link: env.BUILD_URL,
                title: JOB_NAME,
                webhookURL: DISCORD_WEBHOOK
        }
    }
}
