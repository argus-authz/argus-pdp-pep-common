#!/usr/bin/env groovy

@Library('sd')_
def kubeLabel = getKubeLabel()

pipeline {

  agent { label 'java11' }

  options {
    timeout(time: 1, unit: 'HOURS')
    buildDiscarder(logRotator(numToKeepStr: '5'))
  }

  triggers {
    cron('@daily')
  }

  stages {
    stage('build') {
      steps {
        sh 'mvn -U -B clean compile'
      }
    }

    stage('test') {
      steps {
        sh 'mvn -U -B clean test'
      }

      post {
        always {
          junit '**/target/surefire-reports/TEST-*.xml'
          jacoco()
        }
      }
    }

    stage('deploy') {
      steps {
        sh "mvn clean -U -B deploy"
      }
    }

    stage('result') {
      steps {
        script {
          currentBuild.result = 'SUCCESS'
        }
      }
    }
  }

  post {
    failure {
      slackSend color: 'danger', message: "${env.JOB_NAME} - #${env.BUILD_NUMBER} Failure (<${env.BUILD_URL}|Open>)"
    }
    changed {
      script {
        if ('SUCCESS'.equals(currentBuild.result)) {
          slackSend color: 'good', message: "${env.JOB_NAME} - #${env.BUILD_NUMBER} Back to normal (<${env.BUILD_URL}|Open>)"
        }
      }
    }
  }
}
