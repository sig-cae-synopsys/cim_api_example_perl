Notes for perl WS API client example code

This perl client  SOAP XML API
When needed, we have example of the creation of the filter, spec, etc. objects, however usually in the simplest form.
Processing the results demonstrated with commented out print commands.
For additional fields of the spec and result objects refer to the full API documentation.

Only the necessary class and function definitions are provided, the API calls themselves are intended for example snippets.
Helper functions, classes, call parameters, modularization are left to the implementers for simplicity and clarity.
Create update delete calls involve the same spec object creations (see API doc), they are not provided here.

USAGE:
perl wsGetAll.pl

DEPENDENCIES: 
Class-Inspector-1.25
SOAP-Lite-1.19

Dependencies provided in the lib/cpan folder.
For basic logging no change, uncomment debug logging: #use SOAP::Lite +trace => 'debug';

TODO:
To run these examples adjust these connection parameters to match your instance URL and credentials, 
and adjust the example project, stream, defect specifics to match your projects, streams, etc...
Snippet from the TODO section of wsGetAll.pl:
#------------connection details,   
$url="http://localhost:8080";
$userName="admin";
$password="coverity";
#------------configuration, project details,   
# use the getProjects call if don't have one ready
$projectname='gzip';
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


EXAMPLE CALLS:

getAllLdapConfigurations
getAllPermissions
getAllRoles
getAttributes
getBackupConfiguration
getCategoryNames
getCheckerNames
getCommitState
getComponent
getComponentMaps
getDefectStatuses
getGroup
getGroups
getLastUpdateTimes
getLdapServerDomains
getLicenseConfiguration
getLicenseState
getLoggingConfiguration
getProjects
getRole
getServerTime
getSignInConfiguration
getSkeletonizationConfiguration
getSnapshotInformation
getSnapshotPurgeDetails
getSnapshotsForStream
getStreams
getSystemConfig
getTriageStores
getTypeNames
getUser
getUsers
getVersion
getComponentMetricsForProject
getFileContents
getMergedDefectDetectionHistory
getMergedDefectHistory
getMergedDefectsForProjectScope
getMergedDefectsForStreams
getMergedDefectsForSnapshotScope
getStreamDefects
