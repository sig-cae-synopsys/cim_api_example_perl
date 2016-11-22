#!/usr/bin/perl

#use strict;
use FindBin qw($Bin $Script);

BEGIN {
  unshift(@INC, "$Bin/lib/cpan/SOAP-Lite-1.19");
  unshift(@INC, "$Bin/lib/cpan/Class-Inspector-1.25");
  $Script =~ s/\.pl//g;
};

# Uncomment if the base Perl install does not have XML::SAX
#$XML::Simple::PREFERRED_PARSER = 'XML::SAX::PurePerl';

#use Getopt::Long;
use Data::Dumper;
#use Pod::Usage;

#use SOAP::Lite +trace => 'debug';
use SOAP::Lite;

#-------------TODO
#To run these examples adjust these connection parameters 
#to match your instance URL and credentials,
#and adjust the example project, stream, defect
#specifics to match your projects, streams, etc...
#------------connection details,   
$url="http://localhost:8080";
$userName="admin";
$password="coverity";
#------------configuration, project details,   
# use the getProjects call if don't have one ready
$projectname='gzip';
# 
$streamnamepattern='gz*';
# use getStreams with streamnamepattern if you don't have one ready
$streamname='gzip-trunk-misra';
#use getSnapshotsForStream with streamname if you don't have one ready
$snapshotid=10006;
# for getFileContents...
# use getStreamDefects  v[0].defectInstances[0].events[0].fileId.contentsMD5 and filePathname
$filepath='/idirs-7.7.0-misra/gzip-trunk-misra/lib/quotearg.c';
$filecontentsMD5='cd583eecf0af533e6f93f31bb7390065';
# use getComponentMaps, getComponent if you don't have one ready
$componentname1='gzip.lib';
$componentname2='gzip.Other';
# a cid which has instances, triage and detectionhistory
# use one of the getMergedDefect calls if don't have one ready
$cid=10164 ;
#-------------end of TODO
###################### Init using v9 ################################
$api="v9";  

$configProxy = SOAP::Lite->proxy("$url/ws/$api/configurationservice")->uri("http://ws.coverity.com/$api");
$configProxy->transport->timeout(1000);
$configProxy->serializer->register_ns("http://ws.coverity.com/$api", 'ws');
$configProxy->autotype(0);

$defectProxy = SOAP::Lite->proxy("$url/ws/$api/defectservice")->uri("http://ws.coverity.com/$api");
$defectProxy->transport->timeout(1000);
$defectProxy->serializer->register_ns("http://ws.coverity.com/$api", 'ws');
$defectProxy->autotype(0);

##################### SOAP call wrappers (version independent) #######
sub ws_authen_text {
    $auth = SOAP::Header->new( 'name' => 'wsse:Security' );
    $auth->attr( {'xmlns:wsse' => 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd'} );
    $auth->mustUnderstand(1);
    $auth->value(
        \SOAP::Data->value(
            SOAP::Data->name(
                'wsse:UsernameToken' => \SOAP::Data->value(
                    SOAP::Data->name( 'wsse:Username' => $userName ),
                    SOAP::Data->name( 'wsse:Password' => $password )
                )
            )
        )
    );
    $auth;
}
sub to_array {
  ($ref) = @_;
  if (ref($ref) ne 'ARRAY') {
    return @{[$ref]}
  } else {
    return @{$ref}
  }
}
sub ws_call {
  ($proxy, $method_name, $params) = @_;
  my $som;
  if($params) {
    $som = $proxy->call(
      SOAP::Data->name("ws:$method_name") => @{$params},
      ws_authen_text()
    );
  } else {
    $som = $proxy->call(
      SOAP::Data->name("ws:$method_name") => $params,
      ws_authen_text()
    );
  }

  if ($som->fault()) {
    $errorCode = $som->fault()->{'faultcode'};
    $errorMessage = $som->fault()->{'faultstring'};
    print "Web API returned error code $errorCode: calling $method_name: $errorMessage\n";
    #print Dumper($som->fault()->{'detail'}->{'CoverityFault'});
    return -1;
  } else {
	#print Dumper($som);
    # Returns all parameters from a SOAP response, including the result entity itself, as one array.
    return $som->paramsall;
  }
}
###################### 
my $pageSpec = {
    pageSize => 100,
    startIndex => 0
  };

my @params = ({});
my @returns = ({});
#---------------------------------------------------------------ConfigurationService
print "\nGet WebServiceCalls...";
print "\n------------getAllLdapConfigurations";
@params = ({});
@returns = ws_call($configProxy, 'getAllLdapConfigurations',\@params );
#foreach $value (@returns) { print " $value->{baseDN} " ; }

print "\n------------getAllPermissions";
@params = ({});
@returns = ws_call($configProxy, 'getAllPermissions',\@params );
#foreach $value (@returns) { print " $value->{permissionValue} " ; }

print "\n------------getAllRoles";
@params = ({});
@returns = ws_call($configProxy, 'getAllRoles',\@params );
#foreach $value (@returns) { print " $value->{description} " ; }

print "\n------------getAttributes";
@params = ({});
@returns = ws_call($configProxy, 'getAttributes',\@params );
#foreach $value (@returns) { print " $value->{attributeDefinitionId}->{name} " ; }

print "\n------------getAttribute";
@params = (SOAP::Data->name("attributeDefinitionId" => { name => 'Action'}));
$value = ws_call($configProxy, 'getAttribute',\@params );
#print " $value->{displayName} " ; 

print "\n------------getBackupConfiguration";
@params = ({});
$value = ws_call($configProxy, 'getBackupConfiguration',\@params );
#print " $value->{backupLocation} " ; 

print "\n------------getCategoryNames";
@params = ({});
@returns = ws_call($configProxy, 'getCategoryNames',\@params );
#foreach $value (@returns) { print " $value->{displayName} " ; }

print "\n------------getCheckerNames";
@params = ({});
@returns = ws_call($configProxy, 'getCheckerNames',\@params );
#foreach $value (@returns) { print " $value " ; }

print "\n------------getCommitState";
@params = ({});
$value = ws_call($configProxy, 'getCommitState',\@params );
#print " $value->{currentCommitCount} " ; 

print "\n------------getComponent";
@params = (SOAP::Data->name("componentId" => { name => 'Default.Other'}));
$value = ws_call($configProxy, 'getComponent',\@params );
#print " $value->{componentId}->{name} " ; 

print "\n------------getComponentMaps";
@params = (SOAP::Data->name("filterSpec" => { namePattern => '*'}));
@returns = ws_call($configProxy, 'getComponentMaps',\@params );
#foreach $value (@returns) { print " $value->{componentMapId}->{name} " ; }

print "\n------------getDefectStatuses";
@params = ({});
@returns = ws_call($configProxy, 'getDefectStatuses',\@params );
#foreach $value (@returns) { print " $value " ; }

print "\n------------getDeveloperStreamsProjects";
@params = (SOAP::Data->name("filterSpec" => { namePattern => '*',descriptionPattern => '*',includeChildren => 'true',includeStreams => 'true'}));
@returns = ws_call($configProxy, 'getDeveloperStreamsProjects',\@params );
#foreach $value (@returns) { print " $value->{id}->{name} " ; }

print "\n------------getGroup";
@params = (SOAP::Data->name("groupId" => { name => 'Users'}));
$value = ws_call($configProxy, 'getGroup',\@params );
#print " $value->{name}->{displayName} " ; 

print "\n------------getGroups";
@params = (SOAP::Data->name("filterSpec" => { namePattern => '*'}),SOAP::Data->name("pageSpec" => $pageSpec));
$value = ws_call($configProxy, 'getGroups',\@params );
#print " $value->{totalNumberOfRecords} " ; 
#foreach $group ($value->{groups}) { print " $group->{name}->{name} " ; }

print "\n------------getLastUpdateTimes";
@params = ({});
@returns = ws_call($configProxy, 'getLastUpdateTimes',\@params );
#foreach $value (@returns) { print " $value->{featureName}  $value->{lastUpdateDate}, \n" ; }

print "\n------------getLdapServerDomains";
@params = ({});
@returns = ws_call($configProxy, 'getLdapServerDomains',\@params );
#foreach $value (@returns) { print " $value->{name}  " ; }

print "\n------------getLicenseConfiguration";
@params = ({});
$value = ws_call($configProxy, 'getLicenseConfiguration',\@params );
#print " $value->{loc} " ; 

print "\n------------getLicenseState";
@params = ({});
$value = ws_call($configProxy, 'getLicenseState',\@params );
#print " $value->{desktopAnalysisEnabled} " ; 

print "\n------------getLoggingConfiguration";
@params = ({});
$value = ws_call($configProxy, 'getLoggingConfiguration',\@params );
#print " $value->{databaseLogging} " ; 

print "\n------------getProjects";
@params = (SOAP::Data->name("filterSpec" => { namePattern => '*'}));
my @projects = ws_call($configProxy, 'getProjects',\@params );
#foreach $project (@projects) { print " $project->{projectKey}"; }

print "\n------------getRole";
@params = (SOAP::Data->name("roleId" => { name => 'Developer'}));
$value = ws_call($configProxy, 'getRole',\@params );
#print " $value->{description} " ; 

print "\n------------getServerTime";
@params = ({});
$value = ws_call($configProxy, 'getServerTime',\@params );
#print " $value " ; 

print "\n------------getSignInConfiguration";
@params = ({});
$value = ws_call($configProxy, 'getSignInConfiguration',\@params );
#print " $value->{maxFailedSignInAttempts} " ; 

print "\n------------getSkeletonizationConfiguration";
@params = ({});
$value = ws_call($configProxy, 'getSkeletonizationConfiguration',\@params );
#print " $value->{minSnapshotsToKeep} " ; 

print "\n------------getSnapshotInformation";
@params = (SOAP::Data->name("snapshotIds" => { id => $snapshotid}));
@returns = ws_call($configProxy, 'getSnapshotInformation',\@params );
#foreach $value (@returns) { print " $value->{dateCreated}  " ; }

print "\n------------getSnapshotPurgeDetails";
@params = ({});
$value = ws_call($configProxy, 'getSnapshotPurgeDetails',\@params );
#print " $value->{minSnapshotsToKeep} " ; 

print "\n------------getSnapshotsForStream";
@params = (SOAP::Data->name("streamId" => { name => $streamname}));
@returns = ws_call($configProxy, 'getSnapshotsForStream',\@params );
#foreach $value (@returns) { print " $value->{id}  " ; }

print "\n------------getStreams";
@params = (SOAP::Data->name("filterSpec" => { namePattern => $streamnamepattern}));
@returns = ws_call($configProxy, 'getStreams',\@params );
#foreach $value (@returns) { print " $value->{id}->{name}  " ; }

print "\n------------getSystemConfig";
@params = ({});
my $return = ws_call($configProxy, 'getSystemConfig',\@params );
#print "commitPort: $return->{commitPort}\n";

print "\n------------getTriageStores";
@params = (SOAP::Data->name("filterSpec" => { namePattern => '*'}));
@returns = ws_call($configProxy, 'getTriageStores',\@params );
#foreach $value (@returns) { print " $value->{id}->{name}  " ; }

print "\n------------getTypeNames";
@params = ({});
@returns = ws_call($configProxy, 'getTypeNames',\@params );
#foreach $value (@returns) { print " $value->{displayName}  " ; }

print "\n------------getUser";
@params = (SOAP::Data->name("username" => 'admin' ));
$value = ws_call($configProxy, 'getUser',\@params );
#print " $value->{email} " ; 

print "\n------------getUsers";
@params = (SOAP::Data->name("pageSpec" => $pageSpec));
$value = ws_call($configProxy, 'getUsers',\@params );
#print " $value->{totalNumberOfRecords} " ; 
my @users=to_array($value->{users});
#foreach $user (@users) { print "\n $user->{username} $user->{email}  " ; }

print "\n------------getVersion";
@params = ({});
$value = ws_call($configProxy, 'getVersion',\@params );
#print " $value->{internalVersion} " ; 

#---------------------------------------------------------------DefectService

#getComponentMetricsForProject 
print "\n------------getComponentMetricsForProject";
@params = (SOAP::Data->name("projectId" => { name => $projectname}), SOAP::Data->name("componentIds" => { name => $componentname1}), SOAP::Data->name("componentIds" => { name => $componentname2}) );
@returns = ws_call($defectProxy, 'getComponentMetricsForProject',\@params );
#foreach $value (@returns) { print " $value->{totalCount}  " ; }

#getFileContents 
print "\n------------getFileContents";
@params = (SOAP::Data->name("streamId" => { name => "$streamname"}), SOAP::Data->name("fileId" => {filePathname => $filepath ,contentsMD5 => $filecontentsMD5}));
$value = ws_call($defectProxy, 'getFileContents',\@params );
#print Dumper($value); 

print "\n------------getMergedDefectDetectionHistory";
#getMergedDefectDetectionHistory
@params = (SOAP::Data->name("mergedDefectIdDataObj" => {"cid" => $cid}), SOAP::Data->name("streamIds" => { name => "$streamname"}));
@returns = ws_call($defectProxy, 'getMergedDefectDetectionHistory',\@params );
#foreach $value (@returns) { print " $value->{userName}  $value->{streams}->{name} $value->{defectDetection} $value->{detection}" ; }

print "\n------------getMergedDefectHistory";
#getMergedDefectHistory
@params = (SOAP::Data->name("mergedDefectIdDataObj" => {"cid" => $cid}), SOAP::Data->name("streamIds" => { name => "$streamname"}));
@returns = ws_call($defectProxy, 'getMergedDefectHistory',\@params );
#foreach $value (@returns) { print "\n $value->{userModified} $value->{dateModified}" ; }


print "\n------------getMergedDefectsForProjectScope";
#getMergedDefectsForProjectScope ---------------
@params = (SOAP::Data->name("projectId" => { name => "$projectname"}), SOAP::Data->name("pageSpec" => $pageSpec));
$value = ws_call($defectProxy, 'getMergedDefectsForProjectScope',\@params );
#print "\n $value->{totalNumberOfRecords}";
#print Dumper($value); 
@mdids = to_array($value->{mergedDefectIds});
@mds = to_array($value->{mergedDefects});
#foreach $mdid (@mdids) { print "\n $mdid->{cid} $mdid->{mergeKey}" ; }
#foreach $md (@mds) { print "\n $md->{cid} $md->{mergeKey} $md->{checkerName} $md->{cwe} $md->{displayImpact} $md->{functionName} $md->{lastDetected} $md->{lastTriaged}" ; }
                                                      
print "\n------------getMergedDefectsForStreams";
#getMergedDefectsForStreams
@params = (SOAP::Data->name("streamIds" => { name => "$streamname"}), SOAP::Data->name("pageSpec" => $pageSpec), SOAP::Data->name("snapshotScope" => { showSelector => "last()"}));
$value = ws_call($defectProxy, 'getMergedDefectsForStreams',\@params );
#print "\n $value->{totalNumberOfRecords}";
#print Dumper($value); 
@mdids = to_array($value->{mergedDefectIds});
@mds = to_array($value->{mergedDefects});
#foreach $mdid (@mdids) { print "\n $mdid->{cid} $mdid->{mergeKey}" ; }
#foreach $md (@mds) { print "\n $md->{cid} $md->{mergeKey} $md->{checkerName} $md->{cwe} $md->{displayImpact} $md->{functionName} $md->{lastDetected} $md->{lastTriaged}" ; }

print "\n------------getMergedDefectsForProjectScope";
#getMergedDefectsForSnapshotScope
@params = (SOAP::Data->name("projectId" => { name => "$projectname"}), SOAP::Data->name("pageSpec" => $pageSpec), SOAP::Data->name("snapshotScope" => { showSelector => "last()"}));
$value = ws_call($defectProxy, 'getMergedDefectsForProjectScope',\@params );
#print "\n $value->{totalNumberOfRecords}";
#print Dumper($value); 
@mdids = to_array($value->{mergedDefectIds});
@mds = to_array($value->{mergedDefects});
#foreach $mdid (@mdids) { print "\n $mdid->{cid} $mdid->{mergeKey}" ; }
#foreach $md (@mds) { print "\n $md->{cid} $md->{mergeKey} $md->{checkerName} $md->{cwe} $md->{displayImpact} $md->{functionName} $md->{lastDetected} $md->{lastTriaged}" ; }

print "\n------------getStreamDefects";
#getStreamDefects
@params = (SOAP::Data->name("mergedDefectIdDataObjs" => {"cid" => $cid}), SOAP::Data->name("filterSpec" => {  "includeDefectInstances" => 'true', "includeHistory" => 'true',"streamIdList" => {"name" => "$streamname"}}));
my $sd = ws_call($defectProxy, 'getStreamDefects',\@params );
#print Dumper($sd); 
my @dis = to_array($sd->{defectInstances});
my @dsavs = to_array($sd->{defectStateAttributeValues});
my @his = to_array($sd->{history});
#print " $sd->{cid} $sd->{checkerName} $sd->{id}->{id} $sd->{id}->{verNum} $sd->{id}->{defectTriageId} $sd->{id}->{defectTriageVerNum}";
#foreach $h (@his) { print "\n $h->{dateCreated} $h->{userCreated} " ; }
#foreach $dsav (@dsavs) { print "\n $dsav->{attributeDefinitionId}->{name} $dsav->{attributeValueId}->{name}" ; }
foreach $di (@dis) { 
	#print "\n $di->{id}->{id} $di->{component} $di->{function}->{functionDisplayName} $di->{function}->{fileId}->{filePathname} $di->{function}->{fileId}->{contentsMD5}" ; 
	my @evs = to_array($di->{events});
	#foreach $evt (@evs){ #if ($evt->{main} eq 'true'){ #print "\n $evt->{eventKind} $evt->{eventNumber}  $evt->{eventTag} $evt->{main} $evt->{fileId}->{filePathname} $evt->{lineNumber} }
	}

print "\n------------getTrendRecordsForProject";
#getTrendRecordsForProject
@params = (SOAP::Data->name("projectId" => { name => "$projectname"}));
@trs = ws_call($defectProxy, 'getTrendRecordsForProject',\@params );
#foreach $tr (@trs) { print "\n $tr->{metricsDate} $tr->{totalCount} $tr->{triagedCount} $tr->{totalCount} $tr->{inspectedCount} $tr->{dismissedCount} $tr->{newCount} $tr->{outstandingCount} $tr->{fixedCount} " ; }


print "\n------------getTriageHistory";
#getTriageHistory
@params = (SOAP::Data->name("mergedDefectIdDataObj" => {"cid" => $cid}),SOAP::Data->name("triageStoreIds" => {"name" => "Default Triage Store"}));
@trs = ws_call($defectProxy, 'getTriageHistory',\@params );
foreach $tr (@trs) { 
	#print "\n $tr->{id}" ; 
	my @attrs = to_array($tr->{attributes});
	#foreach $attr (@attrs){	print ", $attr->{attributeDefinitionId}->{name} : $attr->{attributeValueId}->{name}   "; }
	}

print "\nDone.";

