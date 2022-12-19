# DevSecOps workflows for container Scan using CICD tools
This workflow will stop the user to push vuln Images in docker registry, you required to add image Scan block in your CICD pipeline before push the Image to Docker registry.
## Pipeline
1. Jenkins Integration
2. AWS CodeBuild Integration
3. GitHub Action Integration

# Jenkins Integration

Let’s add a scanning feature in  [Jenkinsfile](https://github.com/BH-Corporate-Functions/trivy-bh/edit/master/Jenkinsfile):

### Build
1. Install trivy on jenkins server 
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /bin "${Trivy_Version}"


### Environment Variables
```
...
    environment {
          TOKEN = credentials('GH_TOKEN')
          CR_PAT = credentials('DockerCR-cred')
          CR_USR = credentials('dockerhub-user')
          repo_name = 'Your_Container_Repo_Name'
          image_name = 'Your_Image_name'
          tag = 'Image_Tag'
          Packages_lock = 'path of lock files such as Gemfile.lock and package-lock.json'
	  PATH = "/bin:/usr/bin:usr/local/bin"
    }
...

```
### Pipeline step for Container Scan.....
```
...
        stage('Docker Image scan trivy') {
            steps {
                echo 'Downloading shared policies and template file from DevSecOps shared-workflows repo....'
		sh 'git clone https://${TOKEN}@github.com/BH-Corporate-Functions/shared-workflows.git'
		// updating vulnerability database for docker Image Scan
		sh 'trivy image --download-db-only'
		echo ' Generate html report for os, fs  and docker misconfig vuln'
                sh 'mkdir -p reports'
		// Scan for image
		sh 'trivy image  --format template --template "@./shared-workflows/html.tpl" --ignorefile "./shared-workflows/.trivyignore" -o "reports/${image_name}.html" "${repo_name}/${image_name}:${tag}"'
		// Scan for fs (Trivy will look for vulnerabilities based on lock files such as Gemfile.lock and package-lock.json)
		sh 'trivy fs  --format template --template "@./shared-workflows/html.tpl" --ignorefile "./shared-workflows/.trivyignore" -o "reports/Project_name2.html" ${Packages_lock}'
		// Scan for Dockerfile misconfig(custom policies)
		sh 'trivy conf --policy ./shared-workflows/policies --format template --template "@./shared-workflows/html.tpl" -o "reports/Project_name3.html" --ignorefile "/shared-workflows/.trivyignore" --namespaces user ./Dockerfile'
		// Append all reports to Report.html
		sh 'cat reports/Project_name3.html >> reports/Project_name2.html;cat reports/Project_name2.html >> reports/${image_name}.html; rm -rf reports/Project_name* '
		// publish html vuln report
		publishHTML target : [
                    allowMissing: true,
                    alwaysLinkToLastBuild: true,
                    keepAll: true,
                    reportDir: 'reports',
                    reportFiles: '${image_name}.html',
                    reportName: 'Trivy Scan',
                    reportTitles: 'Trivy Scan'
                ]				
		echo 'check for high & critical vuln'
		sh 'trivy image --no-progress --exit-code 1 --severity CRITICAL,HIGH --ignore-unfixed --ignorefile "./shared-workflows/.trivyignore" "${repo_name}/${image_name}:${tag}"'
		sh 'trivy fs --no-progress --exit-code 1 --severity CRITICAL,HIGH --ignore-unfixed --ignorefile "./shared-workflows/.trivyignore" "${Packages_lock}"'	
		sh 'trivy conf --no-progress --exit-code 1 --severity CRITICAL --policy ./shared-workflows/policies  --ignorefile "./shared-workflows/.trivyignore" --namespaces user ./Dockerfile'    
            }
        }			

...
```




# AWS CodeBuild Integration

Let’s add a scanning feature in  AWS [CodeBuild](https://github.com/BH-Corporate-Functions/trivy-bh/blob/master/ImageBuild.yaml):

### Build
1. download the .zip of [repo](https://github.com/BH-Corporate-Functions/shared-workflows)
2. upload it to bucket in same account where you are going to bulid docker image (TRIVY_BUCKET)


### Environment Variables

```
    Environment:
        ComputeType: BUILD_GENERAL1_SMALL
        Image: aws/codebuild/docker:17.09.0
        Type: LINUX_CONTAINER
        PrivilegedMode: true
        EnvironmentVariables:
          - Name: Release_ID
            Value: !Ref ReleaseID
          - Name: AWS_DEFAULT_REGION
            Value: !Ref AWS::Region
          - Name: REPOSITORY_URI
            Value: !Sub ${AWS::AccountId}.dkr.ecr.${AWS::Region}.amazonaws.com/${ECRReponame}
          - Name: TRIVY_BUCKET
            Value: !Ref TRIVY_BUCKET
          - Name: TRIVY_REPORT_BUCKET
            Value:  !Ref TRIVY_REPORT_BUCKET
          - Name: Packages_lock
            Value:  !Ref Packages_lock
          - Name: Trivy_Version
            Value: !Ref TrivyVersion
```

### Pipeline step for Container Scan.....
```
            image_Scan:
              commands:
                - docker image ls
                - aws s3 cp s3://${TRIVY_BUCKET}/shared-workflows-master.zip .
                - unzip  shared-workflows-master.zip
                - cp Dockerfile ./shared-workflows-master/configs
                - echo "Install trivy"
                - curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /bin "${Trivy_Version}"
                - echo "downloading  vulnerability database"
                - trivy image --download-db-only
                - trivy image --format template --template "@./shared-workflows-master/html.tpl" --ignorefile "./shared-workflows-master/.trivyignore" -o "${ECRReponame}-${SCAN_DATE}.html" "${REPOSITORY_URI}:${TAG}"
                - trivy fs  --format template --template "@./shared-workflows-master/html.tpl" --ignorefile "./shared-workflows-master/.trivyignore" -o Report.html ${Packages_lock}'   
                - trivy conf    --policy ./shared-workflows-master/policies --format template --template "@./shared-workflows-master/html.tpl" --ignorefile "./shared-workflows/.trivyignore"  -o  Report1.html --namespaces user ./shared-workflows-master/configs                
                - cat Report1.html >> Report.html; cat Report.html >>"${ECRReponame}-${SCAN_DATE}.html"
                - echo "Uploading Reports to \n\n\ns3://${ANCHORE_REPORT_BUCKET}/Reports/ "
                - aws s3 cp "${ECRReponame}-${SCAN_DATE}.html" s3://${TRIVY_REPORT_BUCKET}/Reports/
                - echo "Check for CRITICAL & HIGH Vulnerabilities\n\n\n\n."
                - trivy image --no-progress --exit-code 1 --severity CRITICAL,HIGH --ignore-unfixed --ignorefile "./shared-workflows-master/.trivyignore"  "${REPOSITORY_URI}:${TAG}"
                - trivy fs  -exit-code 1 --severity CRITICAL,HIGH --format template --template "@./shared-workflows-master/html.tpl" --ignorefile "./shared-workflows-master/.trivyignore" -o Report.html ${Packages_lock}'
                - trivy conf  --exit-code 1 --severity CRITICAL  --policy ./shared-workflows-master/policies  --ignorefile "./shared-workflows-master/.trivyignore" --namespaces user ./shared-workflows-master/configs             
            post_build:
              commands:   
                - echo "Push Image to ${REPOSITORY_URI}"
                - docker image push "${REPOSITORY_URI}:${TAG}"

```
# GitHub Action Integration

Let’s add a scanning feature for GitHub Action [Imagebuild.yaml](https://github.com/BH-Corporate-Functions/trivy-bh/blob/master/.github/workflows/Imagebuild.yaml):

### Build  


### Environment Variables for shared workflow
```
...
name: Docker Image Build
on:
  push:
    branches:
      - master
  workflow_dispatch:
    inputs:
      tag:
        type: string
        description: image tag
        required: true
jobs:
  build:
    uses: BH-Corporate-Functions/shared-workflows/.github/workflows/docker-image-build-scan-push-github.yaml@master
    with:
      # Container Image Name // update it as per project name.
      image_name: "trivy-test"
      # Repo Name
      GHCR_REPO: "ghcr.io/bh-corporate-functions/trivy-bh"
      # Path to the Dockerfile. (default {context}/Dockerfile)
      docker_file_path: "."
      # "location of lock file in git repository (Trivy will look for vulnerabilities based on lock files such as Gemfile.lock and package-lock.json)"  
      Packages_lock: "."
      # Image Tag
      image_tag: ${{ github.event.inputs.tag }}
      # GH Username 
      username: 'github user name'
    secrets: inherit

```
### Pipeline step for Container Scan [docker-image-scan.yaml](https://github.com/BH-Corporate-Functions/shared-workflows/blob/master/.github/workflows/docker-image-build-scan-push-github.yaml)

```
      - name: copy template file from  shared-workflows repo
        run: |
          git clone https://${{ secrets.GH_TOKEN }}@github.com/BH-Corporate-Functions/shared-workflows.git
      - name: copy the docker file to template directory
        run: |
          cp ${{ inputs.docker_file_path }}/Dockerfile ./shared-workflows/configs   
      - name: Install Trivy CLI
        run: |
          curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin v0.31.3
 
      - name: downloading  vulnerability  database
        run: |
          /usr/local/bin/trivy image --download-db-only  
     
      - name: Run Trivy  scan for Docker Image and generate html report
        run: |
          /usr/local/bin/trivy image  --format template --template "@./shared-workflows/html.tpl" --ignorefile "./shared-workflows/.trivyignore" -o Report.html ${{ inputs.GHCR_REPO }}${{ inputs.image_name }}:${{ inputs.image_tag }}
      
      - name: Run Trivy scan for filesystem and generate html report(Trivy will look for vulnerabilities based on lock files such as Gemfile.lock and package-lock.json)
        run: |
          /usr/local/bin/trivy fs --format template --template "@./shared-workflows/html.tpl" --ignorefile "./shared-workflows/.trivyignore" -o Report2.html ${{ inputs.Packages_lock }}
      
      - name: Run Trivy scan for dockerfile 
        run: |
          /usr/local/bin/trivy conf --policy ./shared-workflows/policies --format template --template "@./shared-workflows/html.tpl" -o Report3.html  --namespaces user ./shared-workflows/configs
        
      - name: Append all reports to Report.html
        run: |
          cat Report3.html >> Report2.html;cat Report2.html >> Report.html
      - name: Upload Trivy vulnerabilities Report to artifact
        uses: actions/upload-artifact@v3
        with:
          path: "Report.html"  
      - name: check for Crtical & High vulnerabilities in Docker Image
        run: |
          /usr/local/bin/trivy image --no-progress --exit-code 1 --severity CRITICAL,HIGH --ignore-unfixed --ignorefile "./shared-workflows/.trivyignore" ${{ inputs.GHCR_REPO }}${{ inputs.image_name }}:${{ inputs.image_tag }}
     
      - name: Check for filesystem (Trivy will look for vulnerabilities based on lock files such as Gemfile.lock and package-lock.json)
        run: |
          /usr/local/bin/trivy fs --exit-code 1 --severity CRITICAL,HIGH --ignore-unfixed --ignorefile "./shared-workflows/.trivyignore"  ${{ inputs.Packages_lock }}      
      - name: check for Misconfig in Dockerfile (Optional)
        run: |
          /usr/local/bin/trivy conf --exit-code 1 --severity CRITICAL --policy ./shared-workflows/policies  --namespaces user ./shared-workflows/configs



```
