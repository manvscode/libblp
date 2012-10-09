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
#ifndef _LIBBLP_H_
#define _LIBBLP_H_
#ifdef __cplusplus
extern "C" {
#endif
#include <types.h>
	
#if defined(DLL_EXPORT)
#define _blplib   __declspec( dllexport )
#elif defined(DLL_IMPORT)
#define _blplib   __declspec( dllimport )
#else
#define _blplib 
#endif

#define BLP_DEFAULT_HOST                 ("127.0.0.1")
#define BLP_DEFAULT_PORT                 (8194)
#define BLP_FIELD_TYPE_NONE              (0)
#define BLP_FIELD_TYPE_STRING            (1)
#define BLP_FIELD_TYPE_DECIMAL           (2)
#define BLP_FIELD_TYPE_INTEGER           (3)
#define BLP_FIELD_TYPE_UNSIGNED_INTEGER  (4)
#define BLP_FIELD_TYPE_POINTER           (5)



struct blp;
typedef _blplib struct blp blp_t;
struct security;
typedef _blplib struct security security_t;
struct field;
typedef _blplib struct field field_t;
struct subscription;
typedef _blplib struct subscription subscription_t;

/*
 *   Bloomberg Library 
 */
_blplib blp_t*         blp_create                     ( const char *server, short port );
_blplib void           blp_destroy                    ( blp_t *p_blp );
_blplib unsigned short blp_error_code                 ( const blp_t *p_blp );
_blplib const char*    blp_error                      ( const blp_t *p_blp );
_blplib unsigned short blp_field_count                ( void );
_blplib unsigned short blp_field_type                 ( const char *field );
_blplib const char*    blp_field_description          ( const char *field );
_blplib const char*    blp_field_mneumonic_by_index   ( size_t index );
_blplib const char*    blp_field_description_by_index ( size_t index );

/*
 *   Security Object
 */
_blplib security_t*      security_create                     ( void );
_blplib void             security_destroy                    ( security_t *p_security );
_blplib const char*      security_ticker                     ( const security_t *p_security );
_blplib boolean          security_set_ticker                 ( security_t *p_security, const char *ticker );
_blplib boolean          security_has_field                  ( const security_t *p_security, const char *field );
_blplib size_t           security_field_count                ( const security_t *p_security );
_blplib unsigned short   security_field_type                 ( const security_t *p_security, const char *field );
_blplib const char*      security_field_value_as_string      ( const security_t *p_security, const char *field );
_blplib boolean          security_set_field_value_as_string  ( security_t *p_security, const char *field, const char *value );
_blplib double           security_field_value_as_decimal     ( const security_t *p_security, const char *field );
_blplib boolean          security_set_field_value_as_decimal ( security_t *p_security, const char *field, double value );
_blplib long             security_field_value_as_integer     ( const security_t *p_security, const char *field );
_blplib boolean          security_set_field_value_as_integer ( security_t *p_security, const char *field, long value );
_blplib unsigned long    security_field_value_as_uinteger    ( const security_t *p_security, const char *field );
_blplib boolean          security_set_field_value_as_uinteger( security_t *p_security, const char *field, unsigned long value );
_blplib void*            security_field_value_as_pointer     ( const security_t *p_security, const char *field );
_blplib boolean          security_set_field_value_as_pointer ( security_t *p_security, const char *field, void* value );
_blplib const char*      security_first_field                ( security_t* p_security );
_blplib const char*      security_next_field                 ( security_t* p_security );
_blplib boolean          security_add_override               ( security_t *p_security, const char *field, const char *value );
_blplib boolean          security_remove_override            ( security_t *p_security, const char *field );
_blplib boolean          security_has_override               ( const security_t *p_security, const char *field );
_blplib void             security_clear_overrides            ( security_t *p_security );

/*
 *   Subscription Object
 */
_blplib subscription_t*   subscription_create        ( void );
_blplib void              subscription_destroy       ( subscription_t* p_subscription );
_blplib boolean           subscription_modify        ( subscription_t *p_subscription, const char **securities, size_t number_of_securities, const char **fields, size_t number_of_fields );
_blplib boolean           subscription_end           ( subscription_t *p_subscription );
_blplib boolean           subscription_is_terminated ( const subscription_t* p_subscription );
_blplib double            subscription_interval      ( const subscription_t* p_subscription );
_blplib void              subscription_set_interval  ( subscription_t* p_subscription, double interval );
_blplib boolean           subscription_has_security  ( subscription_t* p_subscription, const char *ticker );
_blplib size_t            subscription_security_count( const subscription_t* p_subscription );
_blplib security_t*       subscription_security      ( subscription_t* p_subscription, const char *ticker );
_blplib security_t*       subscription_first_security( subscription_t* p_subscription );
_blplib security_t*       subscription_next_security ( subscription_t* p_subscription );

/*
 *   Bloomberg Services
 */
_blplib boolean blp_reference_data   ( blp_t *p_blp, security_t *p_security, const char *security, size_t number_of_fields, const char **fields );
_blplib boolean blp_reference_data_v ( blp_t *p_blp, security_t *p_security, const char *security, size_t number_of_fields, ... );
_blplib boolean blp_market_data      ( blp_t *p_blp, subscription_t *p_subscription, const char **securities, size_t number_of_securities, const char **fields, size_t number_of_fields );


#ifdef __cplusplus
} /* external C linkage */
#endif
#endif /* _LIBBLP_H_ */
