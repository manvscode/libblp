/*
 * Copyright (C) 2011 by Joseph A. Marrero and Shrewd LLC. http://www.manvscode.com/
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
#include <blpapi_correlationid.h>
#include <blpapi_event.h>
#include <blpapi_message.h>
#include <blpapi_request.h>
#include <blpapi_session.h>
#include <blpapi_service.h>

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>
#include <assert.h>

#include <hash-map.h>
#include <hash-functions.h>
#include <tree-map.h>
#include <variant.h>
#include "libblp.h"
#if defined(WIN32) || defined(WIN64)
#include <windows.h>
#define ACQUIRE_LOCK( p_obj )  			EnterCriticalSection( (LPCRITICAL_SECTION) &p_obj->crit_section );
#define RELEASE_LOCK( p_obj )  			LeaveCriticalSection( (LPCRITICAL_SECTION) &p_obj->crit_section );
#endif

#define FIELDS_TABLE_SMALL   13
#define FIELDS_TABLE_MEDIUM  23
#define FIELDS_TABLE_LARGE   37

struct blp {
	unsigned short error_num;
	boolean debug;
	blpapi_SessionOptions_t *session_options;
};

struct security {
	hash_map_iterator_t iterator;
	hash_map_t          fields;
	tree_map_t          overrides;
	char*               ticker;

	#if defined(WIN32) || defined(WIN64)
    CRITICAL_SECTION crit_section;
	#endif
};


typedef enum ServiceType {
	ReferenceDataService,
	MarketDataService,            // Market Data Service
	CustomVWAPService,            // The Custom Volume Weighted Average Price (VWAP) Service
	MarketBarSubscriptionService, // Market Bar Subscription Service 
	APIFieldInformationService,   // API Field Information Service
	TechnicalAnalysisService,     // Technical Analysis Service
	SERVICE_TYPE_COUNT
} service_type_t;


static const char *SERVICES[] = {
	"//blp/refdata",
	"//blp/mktdata",
	"//blp/mktvwap",
	"//blp/mktbar",
	"//blp/apiflds",
	"//blp/tasvc",
	NULL
};


struct field {
	variant_t   value;
};

typedef struct blp_field_descriptor {
	const char *mnemonic;
	unsigned char type;
	const char *description;
} blp_field_descriptor_t;

static const blp_field_descriptor_t FIELDS[] = {
	#include "bbfields.h"
};

#define BLP_FIELD_COUNT       (sizeof(FIELDS) / sizeof(blp_field_descriptor_t))

static const char* blp_field_mneumonic_by_index   ( size_t index );
static const char* blp_field_description_by_index ( size_t index );
static const char* blp_service_name           ( service_type_t type );
static boolean     security_set_field_from_bb ( security_t *p_security, const char *field, const char *value );
static boolean     field_initialize           ( const char *field, const char *value, field_t *p_field );
static boolean     string_conversion          ( const char *string, variant_t* p_variant );
static boolean     decimal_conversion         ( const char *string, variant_t* p_variant );
static boolean     integer_conversion         ( const char *string, variant_t* p_variant );
static boolean     unsigned_integer_conversion( const char *string, variant_t* p_variant );
static int         field_descriptor_compare   ( const void *p_left, const void *p_right );
security_t*        subscription_create_security_if_none( subscription_t *p_subscription, const char *ticker );
static size_t      get_time_stamp             (char *buffer, size_t bufSize);

enum ErrorNum {
	NoError,
	FailedToStartSession,
	FailedToOpenService,
	FailedToCreateSessionOptions,
	OutOfMemory,
	ERROR_NUM_COUNT
};

static const char *ERRORS[] = {
	"None",
	"Failed to start session.",
	"Failed to start session.",
	"Out of memory.",
	NULL
};

static int     debug_writer                         ( const char* data, int length, void *stream );
static boolean security_fields_destroy              ( void *key, void *value );
static boolean security_overrides_destroy           ( void *key, void *value );
static boolean subscription_securities_destroy      ( void *key, void *value );
static void    handle_reference_data_event          ( blp_t *p_blp, const blpapi_Event_t *event, security_t *p_security );
static void    handle_reference_data_other_event    ( blp_t *p_blp, const blpapi_Event_t *event );
static void    market_data_event_handler            ( blpapi_Event_t *p_event, blpapi_Session_t *session, void *user_data );
static void    handle_market_data_event             ( blpapi_Event_t *p_event, blpapi_Session_t *session, subscription_t *p_subscription );
static void    handle_market_data_other_event       ( blpapi_Event_t *p_event, blpapi_Session_t *session, subscription_t *p_subscription );

blp_t *blp_create( const char *host, short port )
{
	blpapi_SessionOptions_t *p_session_options = NULL;
	blp_t *p_blp                               = NULL;

	if( *host == '\0'|| host == NULL )
	{
		host = BLP_DEFAULT_HOST;
	}

	if( port == 0 )
	{
		port = BLP_DEFAULT_PORT;
	}

	// Create session options. 
	p_session_options = blpapi_SessionOptions_create( );

	if( p_session_options )
	{
		// Set the host and port for the session. 
		blpapi_SessionOptions_setServerHost( p_session_options, host );
		blpapi_SessionOptions_setServerPort( p_session_options, port );

		// Always connect to the server API
		//blpapi_SessionOptions_setClientMode( p_session_options, BLPAPI_CLIENTMODE_SAPI ); 

		// Reconnect if disconnected
		//blpapi_SessionOptions_setAutoRestartOnDisconnection( p_session_options, 1 /* true */ );
	}
	else
	{
		p_blp->error_num = OutOfMemory;
		return NULL;
	}

	p_blp = (blp_t *) malloc( sizeof(blp_t) );

	if( p_blp )
	{
		p_blp->error_num       = 0;
		p_blp->debug           = FALSE;
		p_blp->session_options = p_session_options;
	}
	else
	{
		p_blp->error_num = OutOfMemory;
		blpapi_SessionOptions_destroy( p_session_options );
	}

	return p_blp;
}

void blp_destroy( blp_t *p_blp )
{
	blpapi_SessionOptions_destroy( p_blp->session_options );
	free( p_blp );
}

unsigned short blp_error_code( const blp_t *p_blp )
{
	if( p_blp )
	{
		return p_blp->error_num;
	}

	return NoError;
}

const char* blp_error( const blp_t *p_blp )
{
	if( p_blp )
	{
		return ERRORS[ p_blp->error_num ];
	}

	return ERRORS[ NoError ];
}

const char *blp_service_name( service_type_t type )
{
	return type < SERVICE_TYPE_COUNT ? SERVICES[ type ] : NULL;
}

unsigned short blp_field_count( void )
{
	return BLP_FIELD_COUNT;
}

unsigned short blp_field_type( const char *field )
{
	blp_field_descriptor_t *p_field_descriptor;

	blp_field_descriptor_t key;

	key.mnemonic    = field;
	//key.type        = 0;
	//key.description = NULL;

	p_field_descriptor = (blp_field_descriptor_t *) bsearch( &key, FIELDS, BLP_FIELD_COUNT, sizeof(blp_field_descriptor_t), field_descriptor_compare );	

	if( p_field_descriptor )
	{
		return p_field_descriptor->type;
	}

	return BLP_FIELD_TYPE_NONE;
}

const char* blp_field_description( const char *field )
{
	blp_field_descriptor_t *p_field_descriptor;

	blp_field_descriptor_t key;

	key.mnemonic    = field;
	key.type        = 0;
	key.description = NULL;

	p_field_descriptor = (blp_field_descriptor_t *) bsearch( &key, FIELDS, BLP_FIELD_COUNT, sizeof(blp_field_descriptor_t), field_descriptor_compare );	

	if( p_field_descriptor )
	{
		return p_field_descriptor->description;
	}

	return NULL;
}

const char* blp_field_mneumonic_by_index( size_t index )
{
	return index < BLP_FIELD_COUNT ? FIELDS[ index ].mnemonic : NULL;
}

const char* blp_field_description_by_index( size_t index )
{
	return index < BLP_FIELD_COUNT ? FIELDS[ index ].description : NULL;
}


int debug_writer( const char* data, int length, void *stream )
{
	assert(data);
	assert(stream);
	return (int) fwrite(data, length, 1, (FILE *)stream);
}


static field_t*         security_field           ( const security_t *p_security, const char *field );
static const variant_t* security_field_value     ( const security_t *p_security, const char *field );

security_t* security_create( void )
{
	security_t *p_security = (security_t *) malloc( sizeof(security_t) );
	
	#if defined(WIN32) || defined(WIN64)
	InitializeCriticalSection( &p_security->crit_section );
	#endif

	ACQUIRE_LOCK( p_security );

	if( p_security )
	{
		memset( &p_security->iterator, 0, sizeof(p_security->iterator) );

		p_security->ticker = NULL;

		if( !hash_map_create( &p_security->fields, FIELDS_TABLE_LARGE, string_hash, security_fields_destroy, (hash_map_compare_function) strcasecmp ) )
		{
			goto fields_failed;
		}

		tree_map_create( &p_security->overrides, security_overrides_destroy, (tree_map_compare_function) strcasecmp );
	}

	
	RELEASE_LOCK( p_security );
	return p_security;

fields_failed:
	free( p_security );
	RELEASE_LOCK( p_security );
	return NULL;
}

void security_destroy( security_t *p_security )
{
	ACQUIRE_LOCK( p_security );

	assert( p_security );

	if( p_security->ticker )
	{
		free( p_security->ticker );
	}

	hash_map_destroy( &p_security->fields );
	tree_map_destroy( &p_security->overrides );

	RELEASE_LOCK( p_security );
	#if defined(WIN32) || defined(WIN64)
	DeleteCriticalSection( &p_security->crit_section );
	#endif

	#if defined(_DEBUG)
	memset( p_security, 0, sizeof(security_t) );
	#endif

	free( p_security );
}

boolean security_fields_destroy( void *key, void *value )
{
	field_t *p_field = (field_t *) value;

	assert( key );
	assert( p_field );

	free( key );
	if( variant_is_string( &p_field->value ) )
	{
		free( variant_string(&p_field->value) );
	}
	free( p_field );
	return TRUE;
}

boolean security_overrides_destroy( void *key, void *value )
{
	assert( key );
	assert( value );
	free( key );
	free( value );
	return TRUE;
}

const char* security_ticker( const security_t *p_security )
{
	assert( p_security );
	return p_security->ticker;
}

boolean security_set_ticker( security_t *p_security, const char *ticker )
{
	assert( p_security );
	ACQUIRE_LOCK( p_security );
	p_security->ticker = _strdup( ticker );
	RELEASE_LOCK( p_security );

	return p_security->ticker != NULL;
}

boolean security_has_field( const security_t *p_security, const char *field )
{
	const field_t *value;
	boolean result = FALSE;

	ACQUIRE_LOCK( p_security );
	assert( p_security );
	result = hash_map_find( &p_security->fields, field, (void **) &value );
	RELEASE_LOCK( p_security );

	return result;
}

size_t security_field_count( const security_t *p_security )
{
	size_t count = 0;

	ACQUIRE_LOCK( p_security );
	assert( p_security );
	count = hash_map_size( &p_security->fields );
	RELEASE_LOCK( p_security );

	return count;
}

field_t *security_field( const security_t *p_security, const char *field )
{
	field_t *value = NULL;

	ACQUIRE_LOCK( p_security );
	assert( p_security );
	hash_map_find( &p_security->fields, field, (void **) &value );
	RELEASE_LOCK( p_security );

	return value;	
}

const variant_t* security_field_value( const security_t *p_security, const char *field )
{
	const field_t *p_field = NULL;

	ACQUIRE_LOCK( p_security );
	assert( p_security );

	if( hash_map_find( &p_security->fields, field, (void **) &p_field ) )
	{
		RELEASE_LOCK( p_security );
		return &p_field->value;
	}

	RELEASE_LOCK( p_security );
	return NULL;	
}

unsigned short security_field_type( const security_t *p_security, const char *field )
{
	const field_t *p_field = NULL;

	ACQUIRE_LOCK( p_security );
	assert( p_security );

	p_field = security_field( p_security, field );

	if( p_field )
	{
		variant_type_t type = variant_type( &p_field->value );
		RELEASE_LOCK( p_security );
		return (unsigned short) type;
	}

	RELEASE_LOCK( p_security );
	return BLP_FIELD_TYPE_NONE;
}

const char* security_field_value_as_string( const security_t *p_security, const char *field )
{
	const variant_t* p_variant = security_field_value( p_security, field );
	const char* result = NULL;
	
	ACQUIRE_LOCK( p_security );
	if( p_variant && p_variant->type == BLP_FIELD_TYPE_STRING )
	{
		result = p_variant->value.string;
	}
	RELEASE_LOCK( p_security );

	return result;
}

boolean security_set_field_value_as_string( security_t *p_security, const char *field, const char *value )
{
	field_t *p_field = NULL;
	boolean result   = FALSE;
	assert( p_security );

	p_field = security_field( p_security, field );

	ACQUIRE_LOCK( p_security );
	if( p_field )
	{
		assert( variant_is_type( &p_field->value, VARIANT_STRING ) );

		if( variant_is_string( &p_field->value ) )
		{
			free( variant_string( &p_field->value ) );
			variant_set_type( &p_field->value, VARIANT_NOT_INITIALIZED );
		}

		result = string_conversion( value, &p_field->value );
	}
	else
	{
		p_field = (field_t *) malloc( sizeof(field_t) );

		assert( p_security );
		assert( field );
		assert( value );

		if( p_field )
		{
			char *field_copy = strdup(field);
		
			memset( p_field, 0, sizeof(field_t) );

			if( !field_copy )
			{
				free( p_field );
				result = FALSE;
				goto done;
			}
		
			if( !string_conversion( value, &p_field->value ) )
			{
				free( p_field );
				free( field_copy );
				result = FALSE;
				goto done;
			}

			result = hash_map_insert( &p_security->fields, field_copy, p_field );
		}
	}

done:
	RELEASE_LOCK( p_security );
	return result;
}

double security_field_value_as_decimal( const security_t *p_security, const char *field )
{
	const variant_t* p_variant = security_field_value( p_security, field );
	double result = 0.0;
	
	ACQUIRE_LOCK( p_security );
	if( p_variant && p_variant->type == BLP_FIELD_TYPE_DECIMAL )
	{
		result = p_variant->value.decimal;
	}
	RELEASE_LOCK( p_security );

	return result;
}

boolean security_set_field_value_as_decimal( security_t *p_security, const char *field, double value )
{
	field_t *p_field = NULL;
	boolean result   = FALSE;
	assert( p_security );

	p_field = security_field( p_security, field );

	ACQUIRE_LOCK( p_security );
	if( p_field )
	{
		assert( variant_is_type( &p_field->value, VARIANT_DECIMAL ) );

		if( variant_is_string( &p_field->value ) )
		{
			free( variant_string( &p_field->value ) );
		}

		variant_set_type( &p_field->value, VARIANT_DECIMAL );
		p_field->value.value.decimal = value;
		result = TRUE;
	}
	else
	{
		p_field = (field_t *) malloc( sizeof(field_t) );

		assert( p_security );
		assert( field );

		if( p_field )
		{
			char *field_copy = strdup(field);
		
			memset( p_field, 0, sizeof(field_t) );

			if( !field_copy )
			{
				free( p_field );
				result = FALSE;
				goto done;
			}

			variant_set_type( &p_field->value, VARIANT_DECIMAL );
			p_field->value.value.decimal = value;

			result = hash_map_insert( &p_security->fields, field_copy, p_field );
		}
	}

done:
	RELEASE_LOCK( p_security );
	return result;
}

long security_field_value_as_integer( const security_t *p_security, const char *field )
{
	const variant_t* p_variant = security_field_value( p_security, field );
	long result = 0L;

	ACQUIRE_LOCK( p_security );	
	if( p_variant && p_variant->type == BLP_FIELD_TYPE_INTEGER )
	{
		result = p_variant->value.integer;
	}
	RELEASE_LOCK( p_security );

	return result;
}

boolean security_set_field_value_as_integer( security_t *p_security, const char *field, long value )
{
	field_t *p_field = NULL;
	boolean result   = FALSE;
	assert( p_security );

	p_field = security_field( p_security, field );

	ACQUIRE_LOCK( p_security );	
	if( p_field )
	{
		assert( variant_is_type( &p_field->value, VARIANT_INTEGER ) );

		if( variant_is_string( &p_field->value ) )
		{
			free( variant_string( &p_field->value ) );
		}

		variant_set_type( &p_field->value, VARIANT_INTEGER );
		p_field->value.value.integer = value;
		result = TRUE;
	}
	else
	{
		p_field = (field_t *) malloc( sizeof(field_t) );

		assert( p_security );
		assert( field );

		if( p_field )
		{
			char *field_copy = strdup(field);
		
			memset( p_field, 0, sizeof(field_t) );

			if( !field_copy )
			{
				free( p_field );
				result = FALSE;
				goto done;
			}

			variant_set_type( &p_field->value, VARIANT_INTEGER );
			p_field->value.value.integer = value;

			result = hash_map_insert( &p_security->fields, field_copy, p_field );
		}
	}

done:
	RELEASE_LOCK( p_security );
	return result;
}

unsigned long security_field_value_as_uinteger( const security_t *p_security, const char *field )
{
	const variant_t* p_variant = security_field_value( p_security, field );
	unsigned long result = 0L;

	ACQUIRE_LOCK( p_security );
	if( p_variant && p_variant->type == BLP_FIELD_TYPE_UNSIGNED_INTEGER )
	{
		result = p_variant->value.unsigned_integer;
	}
	RELEASE_LOCK( p_security );

	return result;
}

boolean security_set_field_value_as_uinteger( security_t *p_security, const char *field, unsigned long value )
{
	field_t *p_field = NULL;
	boolean result   = FALSE;
	assert( p_security );

	p_field = security_field( p_security, field );

	ACQUIRE_LOCK( p_security );
	if( p_field )
	{
		assert( variant_is_type( &p_field->value, VARIANT_UNSIGNED_INTEGER ) );

		if( variant_is_string( &p_field->value ) )
		{
			free( variant_string( &p_field->value ) );
		}

		variant_set_type( &p_field->value, VARIANT_UNSIGNED_INTEGER );
		p_field->value.value.unsigned_integer = value;
		result = TRUE;
	}
	else
	{
		p_field = (field_t *) malloc( sizeof(field_t) );

		assert( p_security );
		assert( field );

		if( p_field )
		{
			char *field_copy = strdup(field);
		
			memset( p_field, 0, sizeof(field_t) );

			if( !field_copy )
			{
				free( p_field );
				result = FALSE;
				goto done;
			}

			variant_set_type( &p_field->value, VARIANT_UNSIGNED_INTEGER );
			p_field->value.value.unsigned_integer = value;

			result = hash_map_insert( &p_security->fields, field_copy, p_field );
		}
	}

done:
	RELEASE_LOCK( p_security );
	return result;
}

void* security_field_value_as_pointer( const security_t *p_security, const char *field )
{
	const variant_t* p_variant = security_field_value( p_security, field );
	void* result = NULL;

	ACQUIRE_LOCK( p_security );
	if( p_variant && p_variant->type == BLP_FIELD_TYPE_POINTER )
	{
		result = p_variant->value.pointer;
	}
	RELEASE_LOCK( p_security );

	return result;
}

boolean security_set_field_value_as_pointer( security_t *p_security, const char *field, void* value )
{
	field_t *p_field = NULL;
	boolean result   = FALSE;
	assert( p_security );

	p_field = security_field( p_security, field );

	ACQUIRE_LOCK( p_security );
	if( p_field )
	{
		assert( variant_is_type( &p_field->value, VARIANT_POINTER ) );

		if( variant_is_string( &p_field->value ) )
		{
			free( variant_string( &p_field->value ) );
		}

		variant_set_type( &p_field->value, VARIANT_POINTER );
		p_field->value.value.pointer = value;
		result = TRUE;
	}
	else
	{
		p_field = (field_t *) malloc( sizeof(field_t) );

		assert( p_security );
		assert( field );
		assert( value );

		if( p_field )
		{
			char *field_copy = strdup(field);
		
			memset( p_field, 0, sizeof(field_t) );

			if( !field_copy )
			{
				free( p_field );
				result = FALSE;
				goto done;
			}

			variant_set_type( &p_field->value, VARIANT_POINTER );
			p_field->value.value.pointer = value;

			result = hash_map_insert( &p_security->fields, field_copy, p_field );
		}
	}

done:
	RELEASE_LOCK( p_security );
	return result;
}

boolean security_set_field_from_bb( security_t *p_security, const char *field, const char *value )
{
	boolean result = FALSE;

	ACQUIRE_LOCK( p_security );
	field_t *p_field = (field_t *) malloc( sizeof(field_t) );

	assert( p_security );
	assert( field );
	assert( value );

	if( p_field )
	{
		char *field_copy = strdup(field);
	
		memset( p_field, 0, sizeof(field_t) );

		if( !field_copy )
		{
			free( p_field );
			result = FALSE;
			goto done;
		}

		if( !field_initialize( field_copy, value, p_field ) )
		{
			free( p_field );
			free( field_copy );
			result = FALSE;
			goto done;
		}

		/* We have to remove any existing field-value pairs and then insert
		 * the new one.
		 */
		hash_map_remove( &p_security->fields, field_copy );

		result = hash_map_insert( &p_security->fields, field_copy, p_field );
	}

done:
	RELEASE_LOCK( p_security );
	return FALSE;
}

const char* security_first_field( security_t* p_security )
{
	const char* result = NULL;

	ACQUIRE_LOCK( p_security );
	hash_map_iterator( &p_security->fields, &p_security->iterator );

	if( hash_map_iterator_next( &p_security->iterator ) )
	{
		result = (const char*) hash_map_iterator_key( &p_security->iterator );
	}
	RELEASE_LOCK( p_security );

	return result;
}

const char* security_next_field( security_t* p_security )
{
	const char* result = NULL;

	ACQUIRE_LOCK( p_security );
	if( hash_map_iterator_next( &p_security->iterator ) )
	{
		result = (const char*) hash_map_iterator_key( &p_security->iterator );
	}
	RELEASE_LOCK( p_security );

	return result;
}

boolean security_add_override( security_t *p_security, const char *field, const char *value )
{
	boolean result = FALSE;	

	ACQUIRE_LOCK( p_security );
	assert( p_security );
	const char *field_copy = _strdup( field );
	const char *value_copy = _strdup( value );
	result = tree_map_insert( &p_security->overrides, field_copy, value_copy );
	RELEASE_LOCK( p_security );

	return result;
}

boolean security_remove_override ( security_t *p_security, const char *field )
{
	boolean result = FALSE;	

	ACQUIRE_LOCK( p_security );
	assert( p_security );
	result = tree_map_remove( &p_security->overrides, field );
	RELEASE_LOCK( p_security );

	return result;
}

boolean security_has_override( const security_t *p_security, const char *field )
{
	boolean result = FALSE;

	ACQUIRE_LOCK( p_security );
	assert( p_security );
	void *value;
	result = tree_map_find( &p_security->overrides, field, &value );
	RELEASE_LOCK( p_security );

	return result;
}

void security_clear_overrides( security_t *p_security )
{
	ACQUIRE_LOCK( p_security );
	assert( p_security );
	tree_map_clear( &p_security->overrides );
	RELEASE_LOCK( p_security );
}

boolean field_initialize( const char *field, const char *value, field_t *p_field )
{
	unsigned char field_type;
	blp_field_descriptor_t *p_field_descriptor;
	boolean result = FALSE;

	blp_field_descriptor_t key;

	key.mnemonic    = field;
	key.type        = 0;
	key.description = NULL;


	p_field_descriptor = (blp_field_descriptor_t *) bsearch( &key, FIELDS, BLP_FIELD_COUNT, sizeof(blp_field_descriptor_t), field_descriptor_compare );	

	field_type = VARIANT_STRING;

	if( p_field_descriptor )
	{
		field_type = p_field_descriptor->type;
	}

	memset( &p_field->value, 0, sizeof(variant_t) );

	switch( field_type )
	{
		case VARIANT_DECIMAL:
			result = decimal_conversion( value, &p_field->value );
			break;
		case VARIANT_INTEGER:
			result = integer_conversion( value, &p_field->value );
			break;
		case VARIANT_UNSIGNED_INTEGER:
			result = unsigned_integer_conversion( value, &p_field->value );
			break;
		case VARIANT_STRING: /* fall through */
		default:
			result = string_conversion( value, &p_field->value );
			break;
	}

	return result;
}

int field_descriptor_compare( const void *p_left, const void *p_right )
{
	const blp_field_descriptor_t *p_left_des;
	const blp_field_descriptor_t *p_right_des;
	p_left_des  = (blp_field_descriptor_t *) p_left;	
	p_right_des = (blp_field_descriptor_t *) p_right;	

	return strncmp( p_left_des->mnemonic, p_right_des->mnemonic, strlen(p_right_des->mnemonic) );
}

boolean string_conversion( const char *string, variant_t* p_variant )
{
	const char* val_copy = strdup( string );
	boolean result = FALSE;

	if( !val_copy )
	{
		goto done;
	}

	assert( variant_type( p_variant ) == VARIANT_NOT_INITIALIZED );

	if( p_variant )
	{
		p_variant->type         = VARIANT_STRING;
		p_variant->value.string = (char *) val_copy;
		result = TRUE;
	}

done:
	return result;
}

boolean decimal_conversion( const char *string, variant_t* p_variant )
{
	if( p_variant )
	{
		p_variant->type          = VARIANT_DECIMAL;
		p_variant->value.decimal = atof( string );
		return TRUE;
	}

	return FALSE;
}

boolean integer_conversion( const char *string, variant_t* p_variant )
{
	if( p_variant )
	{
		p_variant->type          = VARIANT_INTEGER;
		p_variant->value.integer = atol( string );
		return TRUE;
	}

	return FALSE;
}

boolean unsigned_integer_conversion( const char *string, variant_t* p_variant )
{
	if( p_variant )
	{
		p_variant->type                   = VARIANT_UNSIGNED_INTEGER;
		p_variant->value.unsigned_integer = (unsigned long) atol( string );
		return TRUE;
	}

	return FALSE;
}

/*
 *   Subscription Object
 */

struct subscription {
	blp_t*              blp;
	blpapi_Session_t*   session;
	double              interval;
	boolean             is_terminated;
	tree_map_iterator_t securities_iter;
	tree_map_t          securities;
		
	blpapi_CorrelationId_t id;

	#if defined(WIN32) || defined(WIN64)
    CRITICAL_SECTION crit_section;
	#endif
};

subscription_t* subscription_create( void )
{
	subscription_t *p_subscription = (subscription_t *) malloc( sizeof(subscription_t) );
	#if defined(WIN32) || defined(WIN64)
	InitializeCriticalSection( &p_subscription->crit_section );
	#endif

	ACQUIRE_LOCK( p_subscription );
	if( p_subscription )
	{
		p_subscription->blp             = NULL;
		p_subscription->session         = NULL;
		p_subscription->interval        = 10;
		p_subscription->is_terminated   = FALSE;
		p_subscription->securities_iter = NULL;
		tree_map_create( &p_subscription->securities, subscription_securities_destroy, (tree_map_compare_function) strcasecmp );
	}
	RELEASE_LOCK( p_subscription );

	return p_subscription;
}

void subscription_destroy( subscription_t *p_subscription )
{
	ACQUIRE_LOCK( p_subscription );
	assert( p_subscription );

	if( p_subscription->session )
	{
		blpapi_Session_stop( p_subscription->session );
		blpapi_Session_destroy( p_subscription->session );
	}

	tree_map_destroy( &p_subscription->securities );
	RELEASE_LOCK( p_subscription );
	#if defined(WIN32) || defined(WIN64)
	DeleteCriticalSection( &p_subscription->crit_section );
	#endif

	#if defined(_DEBUG)
	memset( p_subscription, 0, sizeof(subscription_t) );
	#endif

	free( p_subscription );
}

boolean subscription_modify( subscription_t *p_subscription, const char **securities, size_t number_of_securities, const char **fields, size_t number_of_fields )
{
	blpapi_Service_t *refDataSvc         = NULL;
	blpapi_Request_t *p_request          = NULL;
	blpapi_Element_t *p_elements         = NULL;
	blpapi_Element_t *p_securities_elems = NULL;
	blpapi_Element_t *p_field_elems      = NULL;
	blpapi_Element_t *p_override_elems   = NULL;
	boolean continue_loop                = TRUE;
	size_t i;

	if( !p_subscription->blp )
	{
		return FALSE;
	}

	if( !p_subscription )
	{
		return FALSE;
	}
	else
	{
		p_subscription->blp = p_subscription->blp;
	}

	// Create the session 
	p_subscription->session = blpapi_Session_create( p_subscription->blp->session_options, market_data_event_handler, NULL, p_subscription /* user data */ );
	
	if( !p_subscription->session )
	{
		p_subscription->blp->error_num = OutOfMemory;
		return FALSE;
	}

	if( 0 != blpapi_Session_start( p_subscription->session ) ) // Start a Session
	{
		blpapi_Session_destroy( p_subscription->session );
		p_subscription->session = NULL;
		p_subscription->blp->error_num        = FailedToStartSession;
		return FALSE;
	}

	// Open Market Data Service
	if( 0 != blpapi_Session_openService( p_subscription->session, blp_service_name( MarketDataService ) ) )
	{
		blpapi_Session_destroy( p_subscription->session );
		p_subscription->session = NULL;
		p_subscription->blp->error_num        = FailedToOpenService;
		return FALSE;
	}

	// ----------------------------------------------------
	blpapi_SubscriptionList_t *subscriptions = NULL;
    char*  security          = NULL;
    char*  field             = NULL;
	size_t number_of_options = 1;

	char opts[ 32 ];

	
	const char **options = (const char **) malloc( sizeof(char*) );

#if defined(WIN32) || defined(WIN64)
	_snprintf_s( opts, sizeof(opts), sizeof(opts) - 1, "interval=%.1lf", p_subscription->interval );
#else
	snprintf( opts, sizeof(opts), "interval=%.1lf", p_subscription->interval );
#endif

	options[ 0 ] = opts;

	subscriptions = blpapi_SubscriptionList_create( );
	assert( subscriptions );

	
	for( i = 0;	i < number_of_securities; i++ )
	{
		const char *ticker = securities[ i ];
		assert( ticker );

		blpapi_SubscriptionList_add( subscriptions, 
									 ticker, 
									 &p_subscription->id, 
									 fields, 
									 options, 
									 number_of_fields, 
									 number_of_options );
    }

	security_t* iter;
	for( iter = subscription_first_security( p_subscription );
	     iter != NULL;
		 iter = subscription_next_security( p_subscription ) )
	{
		boolean found = FALSE;

		for( i = 0; i < number_of_securities; i++ )
		{
			const char *ticker = securities[ i ];

			if( strcasecmp( ticker, security_ticker(iter) ) == 0 )
			{
				found = TRUE;
				break;
			}
		}

		if( !found )
		{
			tree_map_remove( &p_subscription->securities, security_ticker(iter) );
		}
	}

	free( options );

	// Resubscribing to realtime data
	blpapi_Session_resubscribe( p_subscription->session, subscriptions, NULL, NULL );

	// release subscription list
	blpapi_SubscriptionList_destroy( subscriptions );

	return TRUE;
}

boolean subscription_end( subscription_t *p_subscription )
{
	ACQUIRE_LOCK( p_subscription );
	if( p_subscription->session )
	{
		blpapi_Session_stop( p_subscription->session );
		blpapi_Session_destroy( p_subscription->session );
		p_subscription->session = NULL;
	}
	RELEASE_LOCK( p_subscription );

	return TRUE;
}

boolean subscription_securities_destroy( void *p_key, void *p_value )
{
	/* p_key is stored in the security */
	security_t* p_security = (security_t*) p_value;
	security_destroy( p_security );
	return TRUE;
}

boolean subscription_is_terminated( const subscription_t *p_subscription )
{
	boolean result = FALSE;

	ACQUIRE_LOCK( p_subscription );
	assert( p_subscription );
	result = p_subscription->is_terminated;
	RELEASE_LOCK( p_subscription );

	return result;
}

double subscription_interval( const subscription_t *p_subscription )
{
	double interval = 0.0;

	ACQUIRE_LOCK( p_subscription );
	assert( p_subscription );
	interval = p_subscription->interval;
	RELEASE_LOCK( p_subscription );

	return interval;
}

void subscription_set_interval( subscription_t *p_subscription, double interval )
{
	ACQUIRE_LOCK( p_subscription );
	assert( p_subscription );
	p_subscription->interval = interval;
	RELEASE_LOCK( p_subscription );
}

boolean subscription_has_security( subscription_t *p_subscription, const char *ticker )
{
	void *p_security;
	boolean result = FALSE;

	ACQUIRE_LOCK( p_subscription );
	assert( p_subscription );
	assert( ticker );
	result = tree_map_find( &p_subscription->securities, ticker, &p_security );
	RELEASE_LOCK( p_subscription );

	return result;
}

size_t subscription_security_count( const subscription_t* p_subscription )
{
	size_t count = 0;

	ACQUIRE_LOCK( p_subscription );
	assert( p_subscription );
	count = tree_map_size( &p_subscription->securities );
	RELEASE_LOCK( p_subscription );

	return count;
}

security_t* subscription_security( subscription_t *p_subscription, const char *ticker )
{
	security_t *p_security = NULL;
	
	ACQUIRE_LOCK( p_subscription );
	assert( p_subscription );
	assert( ticker );
	if( tree_map_find( &p_subscription->securities, ticker, (void **) &p_security ) )
	{
		assert( p_security );
	}
	RELEASE_LOCK( p_subscription );

	return p_security;
}

security_t* subscription_create_security_if_none( subscription_t *p_subscription, const char *ticker )
{
	security_t *p_security;

	ACQUIRE_LOCK( p_subscription );
	assert( p_subscription );
	assert( ticker );

	if( tree_map_find( &p_subscription->securities, ticker, (void **) &p_security ) )
	{
		assert( p_security );
	}
	else
	{
		p_security = security_create( );
		p_security->ticker = (char*) ticker; /* memory allocated from the BLPAPI_CORRELATION_TYPE_POINTER */
		
		/* key is pointer to ticker in security structure. */
		tree_map_insert( &p_subscription->securities, security_ticker(p_security), p_security );
	}
	RELEASE_LOCK( p_subscription );

	return p_security;
}

security_t* subscription_first_security( subscription_t* p_subscription )
{
	security_t* result = NULL;

	ACQUIRE_LOCK( p_subscription );
	p_subscription->securities_iter = tree_map_begin( &p_subscription->securities );

	if( p_subscription->securities_iter )
	{
		result = (security_t*) p_subscription->securities_iter->value;
	}
	RELEASE_LOCK( p_subscription );

	return result;
}

security_t* subscription_next_security ( subscription_t* p_subscription )
{
	security_t* result = NULL;
	
	ACQUIRE_LOCK( p_subscription );
	if( p_subscription->securities_iter != tree_map_end( ) )
	{
		p_subscription->securities_iter = tree_map_next( p_subscription->securities_iter );

		if( p_subscription->securities_iter )
		{
			result = (security_t*) p_subscription->securities_iter->value;
		}
	}
	RELEASE_LOCK( p_subscription );

	return result;
}



boolean blp_reference_data( blp_t *p_blp, security_t *p_security, const char *security, size_t number_of_fields, const char **fields )
{
	blpapi_Session_t *p_session          = NULL;
	blpapi_Service_t *refDataSvc         = NULL;
	blpapi_Request_t *p_request          = NULL;
	blpapi_Element_t *p_elements         = NULL;
	blpapi_Element_t *p_securities_elems = NULL;
	blpapi_Element_t *p_field_elems      = NULL;
	blpapi_Element_t *p_override_elems   = NULL;
	boolean continue_loop                = TRUE;
	blpapi_CorrelationId_t correlation_id;
	size_t i;
	tree_map_iterator_t override_iter;

	if( !p_blp )
	{
		return FALSE;
	}

	// Create the session 
	p_session = blpapi_Session_create( p_blp->session_options, NULL, NULL, NULL );
	
	if( !p_session )
	{
		p_blp->error_num = OutOfMemory;
		return FALSE;
	}

	if( 0 != blpapi_Session_start( p_session ) ) // Start a Session
	{
		p_blp->error_num = FailedToStartSession;
		blpapi_Session_destroy( p_session );
		return FALSE;
	}

	// Open Reference Data Service
	if( 0 != blpapi_Session_openService( p_session, blp_service_name( ReferenceDataService ) ) )
	{
		blpapi_Session_destroy( p_session );
		p_blp->error_num = FailedToOpenService;
		return FALSE;
	}

	blpapi_Session_getService( p_session, &refDataSvc, blp_service_name( ReferenceDataService ) );

	// Create Reference Data Request using //blp/refdata service
	blpapi_Service_createRequest( refDataSvc, &p_request, "ReferenceDataRequest" );
	assert( p_request );

	p_elements = blpapi_Request_elements( p_request );
	assert( p_elements );

	// Get "securities" element
	blpapi_Element_getElement( p_elements,	&p_securities_elems, "securities", 0 );
	assert( p_securities_elems );

	// Set securities specified on command line
	blpapi_Element_setValueString( p_securities_elems, security, BLPAPI_ELEMENT_INDEX_END );

	// Get "fields" element
	blpapi_Element_getElement( p_elements, &p_field_elems, "fields", 0 );

	// Set fields passed in.
	for( i = 0; i < number_of_fields; i++ )
	{
		const char *field = fields[ i ];
		blpapi_Element_setValueString( p_field_elems, field, BLPAPI_ELEMENT_INDEX_END );
	}

	// Get "overrides" element
    blpapi_Element_getElement( p_elements, &p_override_elems, "overrides", 0 );

	// Set overrides for security.
	for( override_iter = tree_map_begin( &p_security->overrides );
	     override_iter != tree_map_end( ); 
	     override_iter = tree_map_next(override_iter) )
	{
		const char *field = (const char *) override_iter->key;
		const char *value = (const char *) override_iter->value;

		blpapi_Element_t *p_override_elem = NULL;
		blpapi_Element_appendElement( p_override_elems, &p_override_elem );

	    blpapi_Element_setElementString( p_override_elem, "fieldId", 0, field );
		blpapi_Element_setElementString( p_override_elem, "value", 0, value );
	}
	security_clear_overrides( p_security );

	// Print the request on the console.
	if( p_blp->debug )
	{
		blpapi_Element_print( p_elements, &debug_writer, stdout, 0, 4 );
	}

	// Init Correlation ID object
	memset(&correlation_id, '\0', sizeof(correlation_id));
	correlation_id.size = sizeof(correlation_id);
	correlation_id.valueType = BLPAPI_CORRELATION_TYPE_INT;
	correlation_id.value.intValue = (blpapi_UInt64_t)1;

	// Sending request
	blpapi_Session_sendRequest( p_session, p_request, &correlation_id, 0, 0, 0, 0 );

	blpapi_Request_destroy( p_request );


	// Poll for the events from the session until complete response for
	// request is received. For each event received, do the desired processing.
	while( continue_loop )
	{
		blpapi_Event_t *p_event = NULL;
		blpapi_Session_nextEvent( p_session, &p_event, 0 );
		assert(p_event);

		switch( blpapi_Event_eventType(p_event) )
		{
			case BLPAPI_EVENTTYPE_PARTIAL_RESPONSE:
				// Process the partial response event to get data. This event
       		    // indicates that request has not been fully satisfied.
				handle_reference_data_event( p_blp, p_event, p_security );
				break;
			case BLPAPI_EVENTTYPE_RESPONSE: /* final event */
		        // Process the response event. This event indicates that
                // request has been fully satisfied, and that no additional  
                // events should be expected.	
				handle_reference_data_event(p_blp, p_event, p_security );
				continue_loop = FALSE; /* fall through */
				break;
			default:
				// Process events other than PARTIAL_RESPONSE or RESPONSE.
				handle_reference_data_other_event( p_blp, p_event );
				break;
		}

		blpapi_Event_release( p_event );
	}

	blpapi_Session_stop( p_session );
	blpapi_Session_destroy( p_session );

	return TRUE;
}

boolean blp_reference_data_v( blp_t *p_blp, security_t *p_security, const char *security, size_t number_of_fields, ... )
{
	blpapi_Session_t *p_session          = NULL;
	blpapi_Service_t *refDataSvc         = NULL;
	blpapi_Request_t *p_request          = NULL;
	blpapi_Element_t *p_elements         = NULL;
	blpapi_Element_t *p_securities_elems = NULL;
	blpapi_Element_t *p_field_elems      = NULL;
	blpapi_Element_t *p_override_elems   = NULL;
	boolean continue_loop                = TRUE;
	blpapi_CorrelationId_t correlation_id;
	va_list args;
	size_t i;
	tree_map_iterator_t override_iter;

	if( !p_blp )
	{
		return FALSE;
	}

	// Create the session 
	p_session = blpapi_Session_create( p_blp->session_options, NULL, NULL, NULL );
	
	if( !p_session )
	{
		p_blp->error_num = OutOfMemory;
		return FALSE;
	}

	if( 0 != blpapi_Session_start( p_session ) ) // Start a Session
	{
		p_blp->error_num = FailedToStartSession;
		blpapi_Session_destroy( p_session );
		return FALSE;
	}

	// Open Reference Data Service
	if( 0 != blpapi_Session_openService( p_session, blp_service_name( ReferenceDataService ) ) )
	{
		blpapi_Session_destroy( p_session );
		p_blp->error_num = FailedToOpenService;
		return FALSE;
	}

	blpapi_Session_getService( p_session, &refDataSvc, blp_service_name( ReferenceDataService ) );

	// Create Reference Data Request using //blp/refdata service
	blpapi_Service_createRequest( refDataSvc, &p_request, "ReferenceDataRequest" );
	assert( p_request );

	p_elements = blpapi_Request_elements( p_request );
	assert( p_elements );

	// Get "securities" element
	blpapi_Element_getElement( p_elements,	&p_securities_elems, "securities", 0 );
	assert( p_securities_elems );

	// Set securities specified on command line
	blpapi_Element_setValueString( p_securities_elems, security, BLPAPI_ELEMENT_INDEX_END );

	// Get "fields" element
	blpapi_Element_getElement( p_elements, &p_field_elems, "fields", 0 );

	// Set fields passed in.
	va_start( args, number_of_fields );
	for( i = 0; i < number_of_fields; i++ )
	{
		const char *field = va_arg( args, const char * );
		blpapi_Element_setValueString( p_field_elems, field, BLPAPI_ELEMENT_INDEX_END );
	}
	va_end( args );

	// Get "overrides" element
    blpapi_Element_getElement( p_elements, &p_override_elems, "overrides", 0 );

	// Set overrides for security.
	for( override_iter = tree_map_begin( &p_security->overrides );
	     override_iter != tree_map_end( ); 
	     override_iter = tree_map_next(override_iter) )
	{
		const char *field = (const char *) override_iter->key;
		const char *value = (const char *) override_iter->value;

		blpapi_Element_t *p_override_elem = NULL;
		blpapi_Element_appendElement( p_override_elems, &p_override_elem );

	    blpapi_Element_setElementString( p_override_elem, "fieldId", 0, field );
		blpapi_Element_setElementString( p_override_elem, "value", 0, value );
	}
	security_clear_overrides( p_security );

	// Print the request on the console.
	if( p_blp->debug )
	{
		blpapi_Element_print( p_elements, &debug_writer, stdout, 0, 4 );
	}

	// Init Correlation ID object
	memset(&correlation_id, '\0', sizeof(correlation_id));
	correlation_id.size = sizeof(correlation_id);
	correlation_id.valueType = BLPAPI_CORRELATION_TYPE_INT;
	correlation_id.value.intValue = (blpapi_UInt64_t)1;

	// Sending request
	blpapi_Session_sendRequest( p_session, p_request, &correlation_id, 0, 0, 0, 0 );

	blpapi_Request_destroy( p_request );


	// Poll for the events from the session until complete response for
	// request is received. For each event received, do the desired processing.
	while( continue_loop )
	{
		blpapi_Event_t *p_event = NULL;
		blpapi_Session_nextEvent( p_session, &p_event, 0 );
		assert(p_event);

		switch( blpapi_Event_eventType(p_event) )
		{
			case BLPAPI_EVENTTYPE_PARTIAL_RESPONSE:
				// Process the partial response event to get data. This event
       		    // indicates that request has not been fully satisfied.
				handle_reference_data_event( p_blp, p_event, p_security );
				break;
			case BLPAPI_EVENTTYPE_RESPONSE: /* final event */
		        // Process the response event. This event indicates that
                // request has been fully satisfied, and that no additional  
                // events should be expected.	
				handle_reference_data_event(p_blp, p_event, p_security );
				continue_loop = FALSE; /* fall through */
				break;
			default:
				// Process events other than PARTIAL_RESPONSE or RESPONSE.
				handle_reference_data_other_event( p_blp, p_event );
				break;
		}

		blpapi_Event_release( p_event );
	}

	blpapi_Session_stop( p_session );
	blpapi_Session_destroy( p_session );

	return TRUE;
}

void handle_reference_data_event( blp_t *p_blp, const blpapi_Event_t *p_event, security_t *p_security )
{
	blpapi_MessageIterator_t *iter = NULL;
	blpapi_Message_t *message      = NULL;

	assert( p_event );
	assert( p_security );

	iter = blpapi_MessageIterator_create( p_event );
	assert(iter);

	// Iterate through messages received
	while( 0 == blpapi_MessageIterator_next(iter, &message) )
	{
		blpapi_Element_t *referenceDataResponse = NULL;
		blpapi_Element_t *securityDataArray     = NULL;
		size_t numItems = 0;
		size_t i        = 0;

		assert(message);

		referenceDataResponse = blpapi_Message_elements(message);
		assert(referenceDataResponse);
		
		// If a request cannot be completed for any reason, the responseError
		// element is returned in the response. responseError contains detailed 
		// information regarding the failure.
		// Printing the responseError on the console, release the allocated 
		// resources and exiting the program
		if( blpapi_Element_hasElement(referenceDataResponse, "responseError", 0) )
		{
			if( p_blp->debug )
			{
				fprintf(stderr, "has responseError\n");
				blpapi_Element_print(referenceDataResponse, &debug_writer, stdout, 0, 4);
			}
            //blpapi_MessageIterator_destroy(iter);
			//blpapi_Session_destroy(session);
			//exit(1);
			//return
		}
		
		// securityData Element contains Array of ReferenceSecurityData 
		// containing Response data for each security specified in the request.
		blpapi_Element_getElement( referenceDataResponse, &securityDataArray, "securityData", 0 );

		// Get the number of securities received in message
		numItems = blpapi_Element_numValues(securityDataArray);	

		if( p_blp->debug )
		{
			printf("\nProcessing %d security(s)\n", numItems);
		}

		for( i = 0; i < numItems; ++i )
		{
			blpapi_Element_t *securityData          = NULL;
			blpapi_Element_t *securityElement       = NULL;
			blpapi_Element_t *sequenceNumberElement = NULL;
			const char *security                    = NULL;
			int sequenceNumber                      = -1;

			blpapi_Element_getValueAsElement( securityDataArray, &securityData, i );
			
			if( !securityData )
			{
				continue;
			}

			// Get security element
			blpapi_Element_getElement( securityData, &securityElement, "security", 0 );
			assert( securityElement );

			// Read the security specified
			blpapi_Element_getValueAsString( securityElement, &security, 0 );
			assert( security );

			security_set_ticker( p_security, security );


			// reading the sequenceNumber element
			blpapi_Element_getElement( securityData, &sequenceNumberElement, "sequenceNumber", 0 );
			assert( sequenceNumberElement );

			blpapi_Element_getValueAsInt32( sequenceNumberElement, &sequenceNumber, 0 );

			// Checking if there is any Security Error
			if( blpapi_Element_hasElement( securityData, "securityError", 0 ) )
			{
				//If present, this indicates that the specified security could
				// not be processed. This element contains a detailed reason for
				// the failure.
				if( p_blp->debug )
				{
					blpapi_Element_t *securityErrorElement = 0;
					printf( "Security = %s\n", p_security->ticker );
					blpapi_Element_getElement(securityData, &securityErrorElement, "securityError", 0);
					assert(securityErrorElement);
					blpapi_Element_print(securityErrorElement, &debug_writer, stdout, 0, 4);
				}

				continue;
			}

			if( blpapi_Element_hasElement( securityData, "fieldData", 0 ) ) 
			{
				size_t j                           = 0;
				size_t numElements                 = 0;
				blpapi_Element_t *fieldDataElement = NULL;
				blpapi_Element_t *field_Element    = NULL;

				if( p_blp->debug )
				{
					printf( "Security = %s\n", p_security->ticker );
					printf( "sequenceNumber = %d\n", sequenceNumber );
				}

				// Get fieldData Element
				blpapi_Element_getElement(securityData, &fieldDataElement, "fieldData", 0);
				assert(fieldDataElement);
				
				// Get the number of fields received in message
				numElements = blpapi_Element_numElements( fieldDataElement );
				for( j = 0; j < numElements; j++ )
				{
					int dataType = 0;
					blpapi_Element_getElementAt( fieldDataElement, &field_Element, j );
					assert( field_Element );

					dataType = blpapi_Element_datatype( field_Element );

					if( dataType == BLPAPI_DATATYPE_SEQUENCE )
					{
						// read the data for bulk field
						if( p_blp->debug )
						{
							blpapi_Element_print( field_Element, &debug_writer, stdout, 0, 4 );
						}
					}
					else
					{
						// read the data for reference field
						const char *fieldName  = NULL;
						const char *fieldValue = NULL;

						fieldName = blpapi_Element_nameString ( field_Element );
						blpapi_Element_getValueAsString( field_Element, &fieldValue, 0 );

						if( !fieldValue )
						{
							continue;
						}

						security_set_field_from_bb( p_security, fieldName, fieldValue );

						if( p_blp->debug )
						{
							printf( "\t%s = %s\n", fieldName, fieldValue );
						}
					}
				}

				if( p_blp->debug )
				{
					printf("\n");
				}
			}

#if 0
			if (blpapi_Element_hasElement(securityData, "fieldExceptions", 0)){
				blpapi_Element_t *fieldExceptionElement = NULL;
				// Get fieldException Element
				blpapi_Element_getElement(securityData, &fieldExceptionElement, "fieldExceptions", 0);
				assert(fieldExceptionElement);
				// read the field exception errors for invalid fields
				processFieldException(fieldExceptionElement);
			}
#endif
		}
	}

	blpapi_MessageIterator_destroy( iter );
}

void handle_reference_data_other_event( blp_t *p_blp, const blpapi_Event_t *p_event )
{
	blpapi_MessageIterator_t *iter = NULL;
	blpapi_Message_t *message      = NULL;

	assert(p_event);

	// Event has one or more messages. Create message iterator for event
	iter = blpapi_MessageIterator_create( p_event );
	assert( iter );

	// Iterate through messages received
	while( 0 == blpapi_MessageIterator_next(iter, &message) )
	{
		blpapi_Element_t *p_message_elems = NULL;
		assert( message );
		
		// Get the message element and print it on console.
		p_message_elems = blpapi_Message_elements( message );
		assert( p_message_elems );		

		if( p_blp->debug )
		{
			printf( "messageType=%s\n", blpapi_Message_typeString(message) );
			blpapi_Element_print( p_message_elems, &debug_writer, stdout, 0, 4 );
		}
		
		// If session status is sessionTerminated, release allocated resource
		// and exit the program.
		/*
		if (BLPAPI_EVENTTYPE_SESSION_STATUS == blpapi_Event_eventType(p_event)
			&& 0 == strcmp("SessionTerminated",
			blpapi_Message_typeString(message))){
			fprintf(stdout, "Terminating: %s\n", 
							blpapi_Message_typeString(message));
			list_destroy( &secList, FREE_LIST );
			list_destroy( &fieldList, FREE_LIST );
            blpapi_MessageIterator_destroy(iter);
			blpapi_Session_destroy(session);
			exit(1);
		}
		*/
	} 

	// Destroy the message iterator.
	blpapi_MessageIterator_destroy( iter );
}

boolean blp_market_data( blp_t *p_blp, subscription_t *p_subscription,
		const char **securities, size_t number_of_securities,
		const char **fields, size_t number_of_fields )
{
	blpapi_Service_t *refDataSvc         = NULL;
	blpapi_Request_t *p_request          = NULL;
	blpapi_Element_t *p_elements         = NULL;
	blpapi_Element_t *p_securities_elems = NULL;
	blpapi_Element_t *p_field_elems      = NULL;
	blpapi_Element_t *p_override_elems   = NULL;
	boolean continue_loop                = TRUE;
	size_t i;

	if( !p_blp )
	{
		return FALSE;
	}

	if( !p_subscription )
	{
		return FALSE;
	}
	else
	{
		p_subscription->blp = p_blp;
	}

	// Create the session 
	p_subscription->session = blpapi_Session_create( p_blp->session_options, market_data_event_handler, NULL, p_subscription /* user data */ );
	
	if( !p_subscription->session )
	{
		p_blp->error_num = OutOfMemory;
		return FALSE;
	}

	if( 0 != blpapi_Session_start( p_subscription->session ) ) // Start a Session
	{
		blpapi_Session_destroy( p_subscription->session );
		p_subscription->session = NULL;
		p_blp->error_num        = FailedToStartSession;
		return FALSE;
	}

	// Open Market Data Service
	if( 0 != blpapi_Session_openService( p_subscription->session, blp_service_name( MarketDataService ) ) )
	{
		blpapi_Session_destroy( p_subscription->session );
		p_subscription->session = NULL;
		p_blp->error_num        = FailedToOpenService;
		return FALSE;
	}

	// ----------------------------------------------------
	blpapi_SubscriptionList_t *subscriptions = NULL;
    char*  security          = NULL;
    char*  field             = NULL;
	size_t number_of_options = 1;

	char opts[ 32 ];

	
	const char **options = (const char **) malloc( sizeof(char*) );

#if defined(WIN32) || defined(WIN64)
	_snprintf_s( opts, sizeof(opts), sizeof(opts) - 1, "interval=%.1lf", p_subscription->interval );
#else
	snprintf( opts, sizeof(opts), "interval=%.1lf", p_subscription->interval );
#endif

	options[ 0 ] = opts;

	subscriptions = blpapi_SubscriptionList_create( );
	assert( subscriptions );

	for( i = 0;	i < number_of_securities; i++ )
	{
		const char *ticker = securities[ i ];
		assert( ticker );

		// If security name begins with '/', assuming it is not a ticker
		// Initialize Correlation object
		memset( &p_subscription->id, 0, sizeof(p_subscription->id) );
		p_subscription->id.size                   = sizeof(p_subscription->id);
		//p_subscription->id.valueType              = BLPAPI_CORRELATION_TYPE_INT;
		//p_subscription->id.value.intValue         = (blpapi_UInt64_t) string_hash( ticker );
		p_subscription->id.valueType              = BLPAPI_CORRELATION_TYPE_POINTER;
		p_subscription->id.value.ptrValue.pointer = (void *) strdup( ticker );

		blpapi_SubscriptionList_add( subscriptions, 
									 ticker, 
									 &p_subscription->id, 
									 fields, 
									 options, 
									 number_of_fields, 
									 number_of_options );
    }

	free( options );

	// Subscribing to realtime data
	blpapi_Session_subscribe( p_subscription->session, subscriptions, NULL, NULL, NULL );

	// release subscription list
	blpapi_SubscriptionList_destroy( subscriptions );

	return TRUE;
}

void market_data_event_handler( blpapi_Event_t *p_event, blpapi_Session_t *p_session, void *user_data )
{
	subscription_t *p_subscription = (subscription_t *) user_data;
	assert( p_event );
	assert( p_session );
	assert( p_subscription );

	switch( blpapi_Event_eventType( p_event ) )
	{
		case BLPAPI_EVENTTYPE_SUBSCRIPTION_DATA:
		case BLPAPI_EVENTTYPE_SUBSCRIPTION_STATUS:
			// Process events BLPAPI_EVENTTYPE_SUBSCRIPTION_DATA
			// & BLPAPI_EVENTTYPE_SUBSCRIPTION_STATUS.
			handle_market_data_event( p_event, p_session, p_subscription );
			break;
		default:
			// Process events other than BLPAPI_EVENTTYPE_SUBSCRIPTION_DATA
			// or BLPAPI_EVENTTYPE_SUBSCRIPTION_STATUS.
			handle_market_data_other_event( p_event, p_session, p_subscription );
			break;
	}
}

void handle_market_data_event( blpapi_Event_t *p_event, blpapi_Session_t * p_session, subscription_t *p_subscription )
{
	blpapi_MessageIterator_t *iter = NULL;
	blpapi_Message_t *p_message = NULL;
    const char *ticker = NULL;

	assert( p_event );
	assert( p_session );

	// Event has one or more messages. Create message iterator for event
	iter = blpapi_MessageIterator_create( p_event );
	assert( iter );

	// Iterate through messages received
	while( 0 == blpapi_MessageIterator_next(iter, &p_message) )
	{
		blpapi_CorrelationId_t correlationId;
		blpapi_Element_t *p_message_elements  = NULL;
		blpapi_Element_t *p_subscription_data = NULL;
		blpapi_Element_t *marketDataEvents    = NULL;
		security_t* p_security                = NULL;

		assert( p_message );
		
		// get Correlation ID from message
		correlationId = blpapi_Message_correlationId( p_message, 0 );
		if( correlationId.valueType == BLPAPI_CORRELATION_TYPE_POINTER && correlationId.value.ptrValue.pointer != NULL )
		{
			ticker = (char *) correlationId.value.ptrValue.pointer;
		}

		p_message_elements = blpapi_Message_elements( p_message );


		if( ticker && p_message_elements )
		{
			p_security = subscription_create_security_if_none( p_subscription, ticker );
		}

		if( 0 == strcmp( "MarketDataEvents", blpapi_Element_nameString( p_message_elements ) ) )
		{
			size_t numItems = blpapi_Element_numElements( p_message_elements );
			blpapi_Element_t *fieldElement = NULL;
			size_t i;
			int dataType;

			for( i = 0; i < numItems; i++ )
			{
				blpapi_Element_getElementAt( p_message_elements, &fieldElement, i );
				assert( fieldElement );

				dataType = blpapi_Element_datatype( fieldElement );

				if( dataType == BLPAPI_DATATYPE_SEQUENCE )
				{
					// read the data for bulk field
					if( p_subscription->blp->debug )
					{
						blpapi_Element_print( fieldElement, &debug_writer, stdout, 0, 4 );
					}
				}
				else
				{
					// read the data for reference field
					const char *fieldName  = NULL;
					const char *fieldValue = NULL;

					fieldName = blpapi_Element_nameString( fieldElement );
					blpapi_Element_getValueAsString( fieldElement, &fieldValue, 0 );

					if( !fieldValue )
					{
						continue;
					}

					security_set_field_from_bb( p_security, fieldName, fieldValue );

					if( p_subscription->blp->debug )
					{
						printf( "\t%s = %s\n", fieldName, fieldValue );
					}
				}
			}

		}
	
		if( p_subscription->blp->debug )
		{	
			// Get the message element and print it on console.
			blpapi_Element_print( p_message_elements, &debug_writer, stdout, 0, 4 );
			printf("\n");
		}

	}
	blpapi_MessageIterator_destroy(iter);
}

void handle_market_data_other_event( blpapi_Event_t *p_event, blpapi_Session_t * p_session, subscription_t *p_subscription )
{
	blpapi_MessageIterator_t *iter = NULL;
	blpapi_Message_t *p_message    = NULL;

	assert( p_event );
	assert( p_session );

	iter = blpapi_MessageIterator_create( p_event );
	assert( iter );

	// Iterate through messages received
	while( 0 == blpapi_MessageIterator_next(iter, &p_message) )
	{
		blpapi_CorrelationId_t correlationId;
		blpapi_Element_t *messageElements = NULL;
		assert( p_message );

		correlationId   = blpapi_Message_correlationId( p_message, 0 );
		messageElements = blpapi_Message_elements( p_message );
	
		if( p_subscription->blp->debug )
		{	
			blpapi_Element_print( messageElements, &debug_writer, stdout, 0, 4 );
		
		}

		// If session status is session terminated, release allocated resource
		// and exit the program.
		if( BLPAPI_EVENTTYPE_SESSION_STATUS == blpapi_Event_eventType(p_event)
			&& 0 == strcmp("SessionTerminated", blpapi_Message_typeString(p_message)) )
		{
			if( p_subscription->blp->debug )
			{
				fprintf( stdout,	"Terminating: %s\n", blpapi_Message_typeString(p_message) );
			}
			p_subscription->is_terminated = TRUE;
			break;
		}
	}

	blpapi_MessageIterator_destroy( iter );
}

size_t get_time_stamp( char *buffer, size_t bufSize )
{
    const char *format = "%Y-%m-%dT%X";
    time_t now         = time(0);
#ifdef WIN32
	struct tm _timeInfo, *timeInfo;
	localtime_s(&_timeInfo, &now);
	timeInfo = &_timeInfo;

    //tm *timeInfo = localtime_s(&now);
#else
    struct tm _timeInfo;
	struct tm *timeInfo = localtime_r(&now, &_timeInfo);
#endif
    return strftime(buffer, bufSize, format, timeInfo);
}
