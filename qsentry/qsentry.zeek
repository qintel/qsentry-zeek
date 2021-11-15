@load base/frameworks/intel
@load frameworks/intel/seen
@load frameworks/intel/do_notice
@load frameworks/intel/do_expire

module Intel;

export {
    redef enum Intel::Type += { Intel::QSentry };
}

## This file adds mapping between Qintel QSentry Feeds and Zeek.

export {
redef record Intel::MetaData += {
## Maps to the 'comment' fields in QSentry
qsentry_comment: string &optional;
## Maps to the 'service_name' field in QSentry
qsentry_service_name: string &optional;
## Maps to the 'service_type' field in QSentry
qsentry_service_type: string &optional;
## Maps to the 'criminal' field in QSentry
qsentry_criminal: bool &optional;
## Maps to the 'cdn' field in QSentry
qsentry_cdn: bool &optional;
## Maps to the 'asn' field in QSentry
qsentry_asn: int &optional;
};

## QSentry record used for consistent formatting of QSentry values.
type QSentry: record {
## QSentry comments, describes why this indicator is in the list.
description: string &optional &log;
## Service Name is what service this indicator is part of.
service_name: string &optional &log;
## Service Type given in QSentry.
service_type: string &optional &log;
## Criminal is indicative if indicator is used for criminal activities.
criminal: bool &optional &log;
## CDN is indicative is indicator is part of a CDN.
cdn: bool &optional &log;
## ASN is the ASN that the indicator belongs to.
asn: int &optional &log;
};

redef record Info += {
qsentry: QSentry &log &optional;
};

}

hook extend_match(info: Info, s: Seen, items: set[Item]) &priority=5
{
for ( item in items )
{
local tmp: QSentry;

if ( item$meta?$qsentry_comment )
tmp$description = item$meta$qsentry_comment;
if ( item$meta?$qsentry_service_name )
tmp$service_name = item$meta$qsentry_service_name;
if ( item$meta?$qsentry_service_type )
tmp$service_type = item$meta$qsentry_service_type;
if ( item$meta?$qsentry_criminal )
tmp$criminal = item$meta$qsentry_criminal;
if ( item$meta?$qsentry_cdn )
tmp$cdn = item$meta$qsentry_cdn;
if ( item$meta?$qsentry_asn )
tmp$asn = item$meta$qsentry_asn;

info$qsentry = tmp;
}
}
