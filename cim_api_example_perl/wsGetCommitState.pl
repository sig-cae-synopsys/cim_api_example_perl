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

use Getopt::Long;
use Data::Dumper;
use Pod::Usage;

#use SOAP::Lite +trace => 'debug';
use SOAP::Lite;

###################### Init using v9 ################################
my $url="http://localhost:8080";
my $userName="admin";
my $password="coverity";
my $api="v9";  

my $configProxy = SOAP::Lite->proxy("$url/ws/$api/configurationservice")->uri("http://ws.coverity.com/$api");
$configProxy->transport->timeout(1000);
$configProxy->serializer->register_ns("http://ws.coverity.com/$api", 'ws');
$configProxy->autotype(0);


##################### SOAP call wrappers (version independent) #######
sub ws_authen_text {
    my $auth = SOAP::Header->new( 'name' => 'wsse:Security' );
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
  my ($ref) = @_;
  if (ref($ref) ne 'ARRAY') {
    return @{[$ref]}
  } else {
    return @{$ref}
  }
}
sub ws_call {
  my ($proxy, $method_name, $params) = @_;
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
    my $errorCode = $som->fault()->{'faultcode'};
    my $errorMessage = $som->fault()->{'faultstring'};
    print "Web API returned error code $errorCode: calling $method_name: $errorMessage\n";
    #print Dumper($som->fault()->{'detail'}->{'CoverityFault'});
    return -1;
  } else {
	#print Dumper($som);
    # Returns all parameters from a SOAP response, including the result entity itself, as one array.
    return $som->paramsall;
  }
}

my @params = ({});
my $value = ws_call($configProxy, 'getCommitState',\@params );
print "currentCommitCount=$value->{currentCommitCount} \nisAcceptingNewCommits=$value->{isAcceptingNewCommits}" ; 
