#!/usr/bin/perl

#use strict;
use FindBin qw($Bin $Script);

BEGIN {
	unshift( @INC, "$Bin/lib/cpan/SOAP-Lite-1.20/lib" );
	unshift( @INC, "$Bin/lib/cpan/Class-Inspector-1.25" );
	unshift( @INC, "$Bin/lib/cpan/Getopt-Long-2.49.1/lib" );

	$Script =~ s/\.pl//g;
}

# Uncomment if the base Perl install does not have XML::SAX
#$XML::Simple::PREFERRED_PARSER = 'XML::SAX::PurePerl';

use Getopt::Long;
use Data::Dumper;
use Pod::Usage;

use SOAP::Lite;

#use SOAP::Lite +trace => 'debug';

#------------connection details,
$url         = "http://localhost:8080";
$credentials = "admin:coverity";
#------------configuration, project details,
$project_pattern           = '*'; #global pattern passed to API
$stream_pattern				= '.*'; #regex pattern matching the $stream->{id}->{name}
$list_merged_defects       = 0;        # Before drilling down
$list_md_detection_history = 0;
$list_md_history           = 0;
$list_stream_defects       = 0;
$list_sd_history           = 0;
$list_sd_defect_instances  = 0;
$max_retrieved             = 1000;

#------------
GetOptions(
	"max=i"           => \$max_retrieved,               # integer
	"url=s"           => \$url,                         # string
	"credentials=s"   => \$credentials,
	"project=s"       => \$project_pattern,
	"stream=s"       => \$stream_pattern,
	"merged"          => \$list_merged_defects,         # flag
	"mergedhistory"   => \$list_md_history,
	"mergeddetection" => \$list_md_detection_history,
	"streamdefects"   => \$list_stream_defects,
	"streamhistory"   => \$list_sd_history,
	"defectinstances" => \$list_sd_defect_instances
) or die("Error in command line arguments\n");

@cred     = split ':', $credentials;
$userName = shift @cred;
$password = shift @cred;

sub time_stamp{
	($sec,$min,$hour,$mday,$mon,$year) = localtime(time); #,$wday,$yday,$isdst
	return sprintf("%04d-%02d-%02d %02d:%02d:%02d", $year+1900, $mon+1, $mday, $hour, $min, $sec);
}
###################### Init using v9 ################################
$api = "v9";

$configProxy =
  SOAP::Lite->proxy("$url/ws/$api/configurationservice")
  ->uri("http://ws.coverity.com/$api");
$configProxy->transport->timeout(1000);
$configProxy->serializer->register_ns( "http://ws.coverity.com/$api", 'ws' );
$configProxy->autotype(0);

$defectProxy =
  SOAP::Lite->proxy("$url/ws/$api/defectservice")
  ->uri("http://ws.coverity.com/$api");
$defectProxy->transport->timeout(1000);
$defectProxy->serializer->register_ns( "http://ws.coverity.com/$api", 'ws' );
$defectProxy->autotype(0);
##################### SOAP call wrappers (version independent) #######
sub ws_authen_text {
	$auth = SOAP::Header->new( 'name' => 'wsse:Security' );
	$auth->attr(
		{
			'xmlns:wsse' =>
'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd'
		}
	);
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
	if ( ref($ref) ne 'ARRAY' ) {
		return @{ [$ref] };
	}
	else {
		return @{$ref};
	}
}

sub ws_call {
	( $proxy, $method_name, $params ) = @_;
	my $som;
	if ($params) {
		$som = $proxy->call(
			SOAP::Data->name("ws:$method_name") => @{$params},
			ws_authen_text()
		);
	}
	else {
		$som = $proxy->call(
			SOAP::Data->name("ws:$method_name") => $params,
			ws_authen_text()
		);
	}

	if ( $som->fault() ) {
		$errorCode    = $som->fault()->{'faultcode'};
		$errorMessage = $som->fault()->{'faultstring'};
		print
"Web API returned error code $errorCode: calling $method_name: $errorMessage\n";

		#print Dumper($som->fault()->{'detail'}->{'CoverityFault'});
		return -1;
	}
	else {

#print Dumper($som);
# Returns all parameters from a SOAP response, including the result entity itself, as one array.
		return $som->paramsall;
	}
}
##################### API call result processing (version dependent) #######
sub process_md {
	($md) = @_;
	$checkerName              = $md->{checkerName};
	$componentName            = $md->{componentName};
	$displayCategory          = $md->{displayCategory};
	$displayImpact            = $md->{displayImpact};
	$displayIssueKind         = $md->{displayIssueKind};
	$displayType              = $md->{displayType};
	$domain                   = $md->{domain};
	$filePathname             = $md->{filePathname};
	$firstDetected            = $md->{firstDetected};
	$firstDetectedBy          = $md->{firstDetectedBy};
	$firstDetectedDescription = $md->{firstDetectedDescription};
	$firstDetectedSnapshotId  = $md->{firstDetectedSnapshotId};
	$firstDetectedStream      = $md->{firstDetectedStream};
	$firstDetectedTarget      = $md->{firstDetectedTarget};
	$firstDetectedVersion     = $md->{firstDetectedVersion};
	$issueKind                = $md->{issueKind};
	$lastDetected             = $md->{lastDetected};
	$lastDetectedDescription  = $md->{lastDetectedDescription};
	$lastDetectedSnapshotId   = $md->{lastDetectedSnapshotId};
	$lastDetectedTarget       = $md->{lastDetectedTarget};
	$lastDetectedVersion      = $md->{lastDetectedVersion};
	$lastTriaged              = $md->{lastTriaged};
	$mergeKey                 = $md->{mergeKey};
	$occurrenceCount          = $md->{occurrenceCount};

	if ( exists $md->{'cid'} ) {
		$cid = $md->{'cid'};
	}
	else {
		$cid = '';
	}
	if ( exists $md->{'cwe'} ) {
		$cwe = $md->{'cwe'};
	}
	else {
		$cwe = '';
	}

	if ( exists $md->{'functionDisplayName'} ) {
		$functionDisplayName = $md->{'functionDisplayName'};
	}
	else {
		$functionDisplayName = '';
	}
	foreach $dstav ( @{ $md->{defectStateAttributeValues} } ) {
		if ( exists $dstav->{attributeValueId}->{name} ) {
			$mddsa->{ $dstav->{attributeDefinitionId}->{name} } =
			  $dstav->{attributeValueId}->{name};
		}
		else {
			$mddsa->{ $dstav->{attributeDefinitionId}->{name} } =
			  $dstav->{attributeValueId};
		}
	}
	print_md();
}

sub process_stream_defects {
	foreach $sd (@_) {
		$checkerName        = $sd->{checkerName};
		$domain             = $sd->{domain};
		$verNum             = $sd->{id}->{verNum};
		$defectTriageVerNum = $sd->{id}->{defectTriageVerNum};
		$id                 = $sd->{id}->{id};
		$defectTriageId     = $sd->{id}->{defectTriageId};
		$streamId           = $sd->{streamId}->{name};
		foreach my $dstav ( @{ $sd->{defectStateAttributeValues} } ) {

			if ( exists $dstav->{attributeValueId}->{name} ) {
				$sddsa->{ $dstav->{attributeDefinitionId}->{name} } =
				  $dstav->{attributeValueId}->{name};
			}
			else {
				$sddsa->{ $dstav->{attributeDefinitionId}->{name} } =
				  $dstav->{attributeValueId};
			}
		}
		print_stream_defect() if ($list_stream_defects);
		print_sd_history() if ($list_sd_history);
		print_defect_instances() if ($list_sd_defect_instances);
		#print "\n--------------------";
	}
}
##################### API call result printing #######
sub print_md {
	print "\n------------mergedDefect";
	print "\n cid: $cid";
	print " , mergeKey: $mergeKey";
	print " , occurrenceCount: $occurrenceCount";
	print " , domain: $domain";
	print " , cwe: $cwe";
	print " , checkername: $checkerName";
	print " , componentName: $componentName";
	print " , displayCategory: $displayCategory";
	print " , displayImpact: $displayImpact";
	print " , issueKind: $issueKind";
	print " , displayIssueKind: $displayIssueKind";
	print " , displayType: $displayType";
	print " , functionDisplayName: $functionDisplayName" ;
	print " , filePathname: $filePathname";
	print " , lastTriaged: $lastTriaged";
	print " , firstDetected: $firstDetected";
	print " , firstDetectedBy: $firstDetectedBy";
	print " , firstDetectedDescription: $firstDetectedDescription";
	print " , firstDetectedSnapshotId: $firstDetectedSnapshotId";
	print " , firstDetectedStream: $firstDetectedStream";
	print " , firstDetectedTarget: $firstDetectedTarget";
	print " , firstDetectedVersion: $firstDetectedVersion";
	print " , lastDetected: $lastDetected";
	print " , lastDetectedDescription: $lastDetectedDescription";
	print " , lastDetectedSnapshotId: $lastDetectedSnapshotId";
	print " , lastDetectedTarget: $lastDetectedTarget";
	print " , lastDetectedVersion: $lastDetectedVersion";
	for my $k ( keys $mddsa ) {
		print " , $k: ", $mddsa->{$k};
	}
	#print "\n--------------------";
}

sub print_md_triage_history {
	foreach $chg (@defectHistory) {
		print "\n dateModified: ",    $chg->{dateModified};
		print " , affectedStreams: ", $chg->{affectedStreams}->{name};
		print " , userModified: ",    $chg->{userModified};
		print " , comments: ", $chg->{comments} if exists( $chg->{comments} );
		foreach $achg ( @{$chg->{attributeChanges}} ){
 			if (ref($achg)) {
				print "\n   fieldName = " , $achg -> {fieldName};
				print " , oldValue = " , $achg -> {oldValue};
				print " , newValue = " , $achg -> {newValue};
			}
		}
	}
}

sub print_md_detection_history {
	for $detection (@defectDetectionHistory) {
		print "\n at: ",  $detection->{detection};
		print ", stream: ", $detection->{streams}->{name};
		print ", detection: ", $detection->{defectDetection};
		print ", user: ", $detection->{userName};
		print ", snapshot: ", $detection->{snapshotId};
	}
}

sub print_stream_defect {
	print "\n------------streamDefect";
	print "\n id: $id";
	print ", verNum: $verNum";
	print ", defectTriageVerNum: $defectTriageVerNum";
	print ", defectTriageId: $defectTriageId";
	print ", stream: $streamId";
	print ", domain: $domain";
	print ", checkername: $checkerName";
	#print "\n-----streamDefectAttributes: ";
	for my $k ( keys $sddsa ) {
		print ", $k = ", $sddsa->{$k};
	}
}

sub print_sd_history {
	print "\n------------streamDefectHistory";
	if ( ref($sd->{history}) ne 'ARRAY' ) {
		@sdhistory = @{ [$sd->{history}] };
	}
	else {
		@sdhistory = @{$sd->{history}};
	}	
	foreach $chg (@sdhistory ){
		print "\n dateCreated: ", $chg -> {dateCreated} if exists ( $chg -> {dateCreated});
		print " , userCreateded: ", $chg -> {userCreated} if exists ($chg -> {userCreated});
		foreach $av ( @{$chg->{defectStateAttributeValues}} ){
 			if (ref($av)) {
				print ", ",$av->{attributeDefinitionId}->{name},"=",$av->{attributeValueId}->{name};
			}
		}
	}
}

sub print_defect_instances {
	print "\n------------defectInstances";
	if ( ref($sd->{defectInstances}) ne 'ARRAY' ) {
		@defectinstances = @{ [$sd->{defectInstances}] };
	}
	else {
		@defectinstances = @{$sd->{defectInstances}};
	}	
	foreach $di ( @defectinstances ){
		print "\n id: ", $di -> {id} -> {id};
		print ", cwe: ", $di -> {cwe} if exists($di -> {cwe}) ;
		print ", checker: ", $di -> {checkerName} ;
		print ", checker extra: ", $di -> {extra} ;
		print ", domain: ", $di -> {domain} ;
		print ", component: ", $di -> {component} ;
		# issueKinds might be an ARRAY
		#print ", issue kind: ", $di -> {issueKinds} -> {name} if ( (exists($di -> {issueKinds})) && 
		#(exists($di -> {issueKinds} -> {name}) )) ;
		print ", type: ", $di -> {type} -> {displayName} ;
		print ", category: ", $di -> {category} -> {displayName} ;
		print ", impact: ", $di -> {impact} -> {displayName} ;
		print "\n  function: ", $di -> {function} -> {functionDisplayName} if exists($di -> {function} -> {functionDisplayName});
		print "\n  file: ", $di -> {function} -> {fileId} -> {filePathname} if exists($di -> {function} -> {fileId} -> {filePathname});
		print ", md5: ", $di -> {function} -> {fileId} -> {contentsMD5} if exists($di -> {function} -> {fileId} -> {contentsMD5});
		print "\n  local effect: ", $di -> {localEffect} ;
		print "\n  decription: ", $di -> {longDescription} ;
		print "\n  events:";
		if (exists($di -> {events})){
			if ( ref($di -> {events}) ne 'ARRAY' ) {
				@events = @{ [$di -> {events}] };
			}
			else {
				@events = @{ $di -> {events} };
			}			
			foreach $ev ( @events ){
				if ( ref($ev) ne 'HASH'){
					print "\n ERROR:event is not HASH: ",ref($ev);
				}else{					
					print "\n  eventSet: ", $ev -> {eventSet} ;
					print ",  eventNumber: ", $ev -> {eventNumber} ;
					print ",  eventTag: ", $ev -> {eventTag} ;
					print ",  eventKind: ", $ev -> {eventKind} ;
					print ",  main: ", $ev -> {main} ;
					print ",  polarity: ", $ev -> {polarity} ;
					print ",  lineNumber: ", $ev -> {lineNumber} ;
					print ",  main: ", $ev -> {main} ;
					print ",  file: ", $ev -> {fileId} -> {filePathname} if ( exists($ev  -> {fileId} -> {filePathname}) );
					print ",  md5: ", $ev -> {fileId} -> {contentsMD5} if ( exists($ev  -> {fileId} -> {contentsMD5}) );								
				}
			}
		}
		
	}
}
##################### API call filters and spec objects (version dependent) #######
sub project_filter_spec {
	$pfs = {
		'namePattern'        => $project_pattern,
		'includeStreams'     => 'true',
		'includeChildren'    => 'false',
		'descriptionPattern' => '*'
	};
	return $pfs;
}

sub snapshot_scope_spec {

	# Grammar for snapshot show selector
	# Snapshot ID
	# first()
	# last()
	# expression, expression
	# expression..expression
	# lastBefore(expression)
	# lastBefore(date)
	# firstAfter(expression)
	# firstAfter(date)
	# Examples
	# 10017, 10021
	# lastBefore(last())
	# firstAfter(2012-11-30)
	# firstAfter(1 day ago)..last()
	my $snapshot_scope = {};
	my $sss            = {

		#'compareOutDatedStreams' => 'true',
		#'compareSelector' => 'first()',
		#'showOutDatedStreams' => 'true',
		'showSelector' => 'first()..last()'
	};
	return $sss;
}

sub merged_defect_filter_spec {
	my $mdfc = {

	#-------------------------numerical and pick lists
	#'cidList' => [],
	#'componentIdList' => ['Default.Other opt'],
	#'statusNameList' => ["New","Triaged","Dismissed"],
	#'classificationNameList'=> ["Unclassified","Pending","Bug"],
	#'actionNameList'=> ["Undecided","Fix Required", "Modeling Required"],
	#'fixTargetNameList'=> ["Untargeted"],
	#'severityNameList'=> ["Unspecified", "Major", "Minor","Severe","Cosmetic"],
	#'legacyNameList'=> ["False", "True"],
	#'ownerNameList'=> [],
	#'checkerList'=> ['UNINIT_CTOR'],
	#'cweList'=> [457],
	#'checkerCategoryList'=> [],
	#'checkerTypeList'=> [],
	#'impactList'=> [],
	#'issueKindList'=> ['QUALITY'],
	#'componentIdExclude'=> [],
	#'componentIdExclude'=> [],
	#'defectPropertyKey'=> [],
	#'streamExcludeNameList'=> [],
	#'streamIncludeNameList'=> [],
	#---------------patterns, pattern lists
	#'filenamePatternList'=> ['*'],
	#'defectPropertyPattern'=> ['*'],
	#'externalReferencePattern'=> ['*'],
	#'functionNamePattern'=> ['*'],
	#'ownerNamePattern'=> ['*'],
	#---------------dates
		'firstDetectedEndDate'   => '2020-09-05',
		'firstDetectedStartDate' => '2010-09-05',
		'lastDetectedEndDate'    => '2020-09-05',
		'lastDetectedStartDate'  => '2010-09-05',
		'lastFixedEndDate'       => '2020-09-05',
		'lastFixedStartDate'     => '2010-09-05',
		'lastTriagedEndDate'     => '2020-09-05',
		'lastTriagedStartDate'   => '2010-09-05',

		#----------------min,max,counts
		#'maxCid'=> 9000000,
		#'minCid'=> 0,
		'maxOccurrenceCount' => 9000000,
		'minOccurrenceCount' => 0,

#----------------
#'snapshotComparisonField'=> 'Present',
#'streamExcludeQualifier'=> '',
#'streamIncludeQualifier'=> '',
#'mergedDefectIdDataObjs'=> {'cid' => 10001, 'mergeKey' =>'3e446cffe31d964226226520d9ecbf54'},
#------------------complex objects
#'attributeDefinitionValueFilterMap' => {
#	'attributeDefinitionId' => {'name' => 'CVSSv3'},
#	'attributeValueId' => {'name' => '05.3'}
#	}
	};
	return $mdfc;
}

sub stream_defect_filter_spec {
	my %sdfs;
	if ($list_sd_history) {
		$sdfs->{defectStateEndDate}   = '2020-09-05';
		$sdfs->{defectStateStartDate} = '2010-09-05';
		$sdfs->{includeHistory}       = 'true';
	}
	if ($list_sd_defect_instances) {
		$sdfs->{includeDefectInstances} = 'true';
	}
	$sdfs->{streamIds}->{name} = $stream->{id}->{name};
	return $sdfs;
}
###################### Main logic
my @params  = ( {} );
my @returns = ( {} );
my $now = time_stamp();
my %mddsa;
print time_stamp()," Project Pattern: '$project_pattern' StreamName Regex: '$stream_pattern'\n";
print time_stamp()," getProjects\n";
$filterspec = project_filter_spec();
@params = ( SOAP::Data->name( "filterSpec" => $filterspec ) );
my @projects = ws_call( $configProxy, 'getProjects', \@params );

foreach $project (@projects) {
	print time_stamp()," Project Key:$project->{projectKey}, Name: $project->{id}->{name} \n";
	if ( exists $project->{'streams'} ) {
		my $merged_defect_filter = merged_defect_filter_spec();
		my $snapshot_scope       = snapshot_scope_spec();
		foreach $stream ( @{ $project->{'streams'} } ) {
			print time_stamp(),"\nStream: $stream->{id}->{name} , ";
			if ($stream->{id}->{name} =~ /$stream_pattern/) {
				print " match!";
				$mds_retrieved = 0;
				$totalRecords  = 0;
				print "\n",time_stamp()," getMergedDefectsForStreams";
				do {
					@params = (
						SOAP::Data->name(
							"streamIds" => { name => $stream->{id}->{name} }
						),
						SOAP::Data->name( "filterSpec" => $merged_defect_filter ),
						SOAP::Data->name(
							"pageSpec" =>
							  { pageSize => 1, startIndex => $mds_retrieved }
						),
						SOAP::Data->name( "snapshotScope" => $snapshot_scope )
					);
					my $mergedDefects =
					  ws_call( $defectProxy, 'getMergedDefectsForStreams',
						\@params );
					last if !( exists $mergedDefects->{totalNumberOfRecords} );
					$totalRecords = $mergedDefects->{totalNumberOfRecords};
					print "\ntotalrecords: $totalRecords " if $mds_retrieved < 1;
					@mdids  = $mergedDefects->{mergedDefectIds};
					@mds    = $mergedDefects->{mergedDefects};
					$mdsize = @mdids;
					$mds_retrieved += $mdsize;
	
					foreach $md (@mds) {
						if ($list_merged_defects) {
							process_md($md);
						}
						if ($list_md_history) {
							print "\n------------history";
							@params = (
								SOAP::Data->name(
									"mergedDefectIdDataObj" =>
									  { mergeKey => $md->{mergeKey} }
								),
								SOAP::Data->name(
									"streamIds" => { name => $stream->{id}->{name} }
								)
							);
							@defectHistory =
							  ws_call( $defectProxy, 'getMergedDefectHistory',
								\@params );
							print_md_triage_history();
						}
						if ($list_md_detection_history) {
							print "\n------------detectionHistory";
							@params = (
								SOAP::Data->name(
									"mergedDefectIdDataObj" =>
									  { mergeKey => $md->{mergeKey} }
								),
								SOAP::Data->name(
									"streamIds" => { name => $stream->{id}->{name} }
								)
							);
							@defectDetectionHistory = ws_call( $defectProxy,
								'getMergedDefectDetectionHistory', \@params );
	
							print_md_detection_history();
						}
						if ($list_stream_defects || $list_sd_history || $list_sd_defect_instances) {		
							print "\n------------streamDefects";
							$streamDefectFilterSpec = stream_defect_filter_spec();
							@params                 = (
								SOAP::Data->name(
									"mergedDefectIdDataObjs" =>
									  { mergeKey => $md->{mergeKey} }
								),
								SOAP::Data->name(
									"filterSpec" => $streamDefectFilterSpec
								)
							);
							my @streamDefects =
							  ws_call( $defectProxy, 'getStreamDefects', \@params );
							process_stream_defects(@streamDefects);
						}
					}
				  } while ( ( $mds_retrieved < $totalRecords )
					and ( $mds_retrieved < $max_retrieved ) );
				print "\nprocessed $mds_retrieved mergedDefects for stream: $stream->{id}->{name}.\n";
			} 

		}
	}
}
print time_stamp()," Done.\n";

