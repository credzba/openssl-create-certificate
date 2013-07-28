/* Certificate creation. Demonstrates some certificate related
 * operations.
 */

#include <iostream>
#include <locale.h>
#include <exception>

#include <openssl/crypto.h>
#include <openssl/pem.h>
#include <openssl/conf.h>
#include <openssl/x509v3.h>
#ifndef OPENSSL_NO_ENGINE
#include <openssl/engine.h>
#endif

#include <string>
#include <boost/program_options.hpp>
using namespace boost::program_options;
#include <boost/date_time.hpp>
#include <boost/regex.hpp>
#include <time.h>

#include <boost/shared_ptr.hpp>
typedef boost::shared_ptr<X509> X509_PTR;
typedef boost::shared_ptr<EVP_PKEY> EVP_PKEY_PTR;

class OpenSSLError : public std::exception {
public:
    OpenSSLError(const std::string& errorString)
        : _errorString(errorString)
    {}
    virtual ~OpenSSLError() throw() {}

    virtual const char* what() const throw() {
        return _errorString.c_str();
    }
private:
    std::string _errorString;
};


namespace {
    int mkcert(X509_PTR x509p, EVP_PKEY_PTR pkeyp, unsigned int bits,
               const boost::posix_time::ptime& beginDate,
               const boost::posix_time::ptime& endDate,
               unsigned long serial,
               const std::string& cn,
               const std::string& st="",
               const std::string& o="",
               const std::string& ou="",
               const std::string& l="",
               const std::string& c=""
              );
    void set_begindate(X509_PTR  cert, const boost::posix_time::ptime& begindDate);
    void set_enddate(X509_PTR  cert, const boost::posix_time::ptime& notAfterDate);
    unsigned long set_serial(X509_PTR  cert, unsigned long serial);
    void set_subject(X509_PTR  cert, 
                     const std::string& cn,
                     const std::string& st="",
                     const std::string& o="",
                     const std::string& ou="",
                     const std::string& l="",
                     const std::string& c=""
                    );
    int add_ext(X509_PTR cert, int nid, char *value);
    boost::posix_time::ptime getBeginDate(const variables_map& options_map);
    boost::posix_time::ptime getEndDate(const variables_map& options_map);
};

int main(int argc, char **argv)	{

    variables_map options_map;
    std::string out;
    std::string key;
    unsigned int bits=512;
    std::string cn;
    std::string l;
    std::string st;
    std::string o;
    std::string ou;
    std::string c;

    // Parse argument values 
    try {
        options_description desc("Options");
        desc.add_options()
        ("help", "print help messages")
        ("days,d", value<unsigned int>(), "number of days valid")
        ("years,y", value<unsigned int>(), "number of years valid")
        ("enddate,e", value<std::string>(), "date certificate expires")
        ("bits,b", value<unsigned int>(&bits), "number of bits to use for encryption")
        ("out,o", value<std::string>(&out), "filename to write cert to")
        ("key,k", value<std::string>(&key), "private key to use for generation")
        ("serial,s", value<unsigned long>(), "serial number")
        ("begindate,sd", value<std::string>(), "date at which the certificate becomes valid")
        ("CN,cn", value<std::string>(&cn), "certificate owners common name")
        ("L,l", value<std::string>(&l), "certificate owners locality")
        ("ST,st", value<std::string>(&st), "certificate owners state of residence")
        ("O,o", value<std::string>(&o), "organization to which the certificate issuer belongs")
        ("OU,ou", value<std::string>(&ou), "organization unit to which the certificate issuer belongs")
        ("C,c", value<std::string>(&c), "certificate owners country of residence")
        ;
        try {
            store(parse_command_line(argc, argv, desc), options_map);
            if ( options_map.count("help") ) {
                std::cout << desc << std::endl;
                exit(4);
            }
            notify(options_map);
        }
        catch (const error& e) {
            std::cout << "some parse error " << e.what() << std::endl; 
            throw;
        }
    }
    catch (const error& e) {
        std::cout << "some other parse error " << e.what() << std::endl; 
        throw;
    }
    

    //  build certificate
    if (out.empty()) {
        std::cout << "--out option must be specified with the name of the output certificate file" 
                  << std::endl;
        exit(16);
    }
    if (key.empty()) {
        std::cout << "--key option must be specified with the name of the private key to be used for certificate encryption" 
                  << std::endl;
        exit(16);
    }

    if (cn.empty()) {
        std::cout << "--CN option must be specified to have a valid certificate" << std::endl;
        exit(16);
    }

    // load private key
    FILE* key_file = fopen(key.c_str(), "r");
    if (key_file == NULL) {
        std::cout << "Error opening " << key << ", " << strerror(errno) << std::endl;
        exit(16);
    }
    EVP_PKEY* pkey_temp = PEM_read_PrivateKey( key_file, 
                                               &pkey_temp,
                                               NULL,
                                               NULL);
    fclose(key_file);
    if (pkey_temp == NULL) {
        std::cout << "unable to open private key file " << key << std::endl;
        exit(16);
    }

	EVP_PKEY_PTR pkey(pkey_temp,
                      EVP_PKEY_free
                     );


    
    // route all io to memory
	BIO *bio_err;
	CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);
	bio_err=BIO_new(BIO_s_mem());

    // build blank certificate
	X509_PTR x509(X509_new(), X509_free);
    if (x509 == NULL) {
            std::cout << "Unable to generate x509 certificate" << std::endl;
            exit(16);
        }

    boost::posix_time::ptime beginDate = getBeginDate(options_map);
    boost::posix_time::ptime endDate = getEndDate(options_map);

    unsigned int serial=0;
    if (options_map.count("serial")) {
        try {
            serial = options_map["serial"].as<unsigned long>();
        }
        catch(...) {}
    } 

	if (!mkcert(x509, pkey, bits,
                beginDate,
                endDate,
                serial,
                cn,
                st,
                o,
                ou,
                l,
                c ) ) {
        std::cout << "unable to create certificate" << std::endl;
        exit(16);
    }

	//RSA_print_fp(stdout,pkey->pkey.rsa,0);
	//X509_print_fp(stdout,x509);
	//PEM_write_PrivateKey(stdout,pkey,NULL,NULL,0,NULL, NULL);

    FILE* out_file = fopen(out.c_str(), "w");
    if (out_file != NULL) {
        PEM_write_X509(out_file, x509.get());
        fclose(out_file);
    } else {
        std::cout << "Error opening " << out << ", " << strerror(errno) << std::endl;
        exit(16);
    }


    // clean up everything
	ENGINE_cleanup();
	CRYPTO_cleanup_all_ex_data();
	CRYPTO_mem_leaks(bio_err);
	BIO_free(bio_err);

	return(0);    
	}


namespace {

    int mkcert(X509_PTR x509p, EVP_PKEY_PTR pk, unsigned int bits,
               const boost::posix_time::ptime& beginDate,
               const boost::posix_time::ptime& endDate,
               unsigned long serial,
               const std::string& cn,
               const std::string& st,
               const std::string& o,
               const std::string& ou,
               const std::string& l,
               const std::string& c
              ) {

        if (endDate < beginDate) {
            throw OpenSSLError("Begin date must be less than end date");
        }
  
        RSA* rsa = RSA_generate_key(bits, RSA_F4, NULL, NULL);
        if (!EVP_PKEY_assign_RSA(pk.get(), rsa))
		{
            throw OpenSSLError("Unable to generate rsa key");
		}

        X509_set_version(x509p.get(), 2);

        set_serial(x509p, serial);

        set_begindate(x509p, beginDate);

#if 0
        X509_time_adj_ex(X509_get_notAfter(cert.get()), days, 0, NULL);
        unsigned int days=30;
        if (options_map.count("days")) {
            days = options_map["days"].as<unsigned int>();
        }
#endif
        
        set_enddate(x509p, endDate);
        
        X509_set_pubkey(x509p.get(), pk.get());
        
        set_subject(x509p,
                    cn,
                    st,
                    o,
                    ou,
                    l,
                    c );
        
        /* Add various extensions: standard extensions */
        add_ext(x509p, NID_basic_constraints, (char*)"critical,CA:TRUE");
        add_ext(x509p, NID_key_usage, (char*)"critical,keyCertSign,cRLSign");
        
        add_ext(x509p, NID_subject_key_identifier, (char*)"hash");
        add_ext(x509p, NID_authority_key_identifier, (char*)"keyid");
        
        return X509_sign(x509p.get(), pk.get(), EVP_sha1());
    }
    
    void set_begindate(X509_PTR  cert, const boost::posix_time::ptime& notBeforeDate) {

        boost::posix_time::time_facet *facet = new boost::posix_time::time_facet("%y%m%d%H%M%SZ");
        std::ostringstream strNotBefore;
        strNotBefore.imbue(std::locale(std::locale::classic(), facet));
        strNotBefore << notBeforeDate; 
        std::cout << "not before " << notBeforeDate << std::endl;
        std::cout << "not before " << strNotBefore.str() << std::endl;
        ASN1_UTCTIME* notBefore = ASN1_UTCTIME_new();
        ASN1_UTCTIME_set_string(notBefore, strNotBefore.str().c_str());
        int success = X509_set_notBefore(cert.get(), notBefore);
        if (!success) {
            std::cout << "Unable to set certificate begin date to " 
                      << notBeforeDate
                      << std::endl;
        }
    }

    void set_enddate(X509_PTR  cert, const boost::posix_time::ptime& notAfterDate) {
        boost::posix_time::time_facet *facet = new boost::posix_time::time_facet("%y%m%d%H%M%SZ");
        std::ostringstream strNotAfter;
        strNotAfter.imbue(std::locale(std::locale::classic(), facet));
        strNotAfter << notAfterDate; 

        ASN1_UTCTIME* notAfter = ASN1_UTCTIME_new();
        ASN1_UTCTIME_set_string(notAfter, strNotAfter.str().c_str());
        int success = X509_set_notAfter(cert.get(), notAfter);
        if (!success) {
            std::cout << "Unable to set certificate end date to " 
                      << notAfterDate
                      << std::endl;
        }

    }

	
    unsigned long set_serial(X509_PTR  cert, unsigned long serial) {
        if (serial == 0) {
            srand (time(NULL));
            serial = rand();
        }
        ASN1_INTEGER_set(X509_get_serialNumber(cert.get()), serial);
        return serial;
    }

    void set_subject(X509_PTR  cert, 
                     const std::string& cn,
                     const std::string& st,
                     const std::string& o,
                     const std::string& ou,
                     const std::string& l,
                     const std::string& c
                    ) {
        X509_NAME *name = X509_get_subject_name(cert.get());

        // CN is required value
        if (cn.length() > 0) {
            int success = X509_NAME_add_entry_by_txt(name,"CN",
                                                     MBSTRING_ASC, (const unsigned char*) cn.c_str(), -1, -1, 0);
            if (!success) {
                throw OpenSSLError("Unable to add CN to subject");
            }
        } else {
            throw OpenSSLError("CN is required");
        }

        if (st.length() > 0) {
            int success = X509_NAME_add_entry_by_txt(name,"ST",
                                                     MBSTRING_ASC, (const unsigned char*) st.c_str(), -1, -1, 0);
            if (!success) {
                throw OpenSSLError("Unable to add ST to subject");
            }
        }

        if (ou.length() > 0) {
            int success = X509_NAME_add_entry_by_txt(name,"OU",
                                                     MBSTRING_ASC, (const unsigned char*) ou.c_str(), -1, -1, 0);
            if (!success) {
                throw OpenSSLError("Unable to add OU to subject");
            }
        }

        if (o.length() > 0) {
            int success = X509_NAME_add_entry_by_txt(name,"O",
                                                     MBSTRING_ASC, (const unsigned char*) o.c_str(), -1, -1, 0);
            if (!success) {
                throw OpenSSLError("Unable to add O to subject");
            }
        }

        if (l.length() > 0) {
            int success = X509_NAME_add_entry_by_txt(name,"L",
                                                     MBSTRING_ASC, (const unsigned char*) l.c_str(), -1, -1, 0);
            if (!success) {
                throw OpenSSLError("Unable to add L to subject");
            }
        }

        if (c.length() > 0) {
            int success = X509_NAME_add_entry_by_txt(name,"C",
                                                     MBSTRING_ASC, (const unsigned char*) c.c_str(), -1, -1, 0);
            if (!success) {
                throw OpenSSLError("Unable to add C to subject");
            }
        }

        /* Its self signed so set the issuer name to be the same as the
         * subject.
         */
        X509_set_issuer_name(cert.get(), name);

    }



    /* Add extension using V3 code: we can set the config file as NULL
     * because we wont reference any other sections.
     */

    int add_ext(X509_PTR cert, int nid, char *value)
	{
        X509_EXTENSION *ex;
        X509V3_CTX ctx;
        /* This sets the 'context' of the extensions. */
        /* No configuration database */
        X509V3_set_ctx_nodb(&ctx);
        /* Issuer and subject certs: both the target since it is self signed,
         * no request and no CRL
         */
        X509V3_set_ctx(&ctx, cert.get(), cert.get(), NULL, NULL, 0);
        ex = X509V3_EXT_conf_nid(NULL, &ctx, nid, value);
        if (!ex)
		return 0;

        X509_add_ext(cert.get(), ex, -1);
        X509_EXTENSION_free(ex);
        return 1;
	}


    boost::posix_time::ptime getBeginDate(const variables_map& options_map ) {
        boost::posix_time::ptime inputNotBefore = boost::posix_time::second_clock::universal_time(); 
        inputNotBefore = inputNotBefore - boost::gregorian::days(1);
        if (options_map.count("begindate")) {
            std::string inputNotBeforeStr = options_map["begindate"].as<std::string>();

            const char* inputs[] = {
                "%y%m%d%H%M%SZ",
                "%y%m%d%H%M%S",
                "%m/%d/%Y",
                "%Y%m%d%H%M%S",
                "%Y-%m-%d %H:%M:%S%Q",
                "%Y%m%d%H%M",
                "%a %b %d %H:%M:%S UTC %Y",
                "%Y%m%d"
            };
            const size_t formats = sizeof(inputs)/sizeof(inputs[0]);

            bool failedLookup=true;
            for (size_t i=0; i<formats; i++) {
                std::locale testLocale(std::locale::classic(), 
                                       new boost::posix_time::time_input_facet(inputs[i]));
                std::istringstream is(inputNotBeforeStr);
                is.imbue(testLocale);
                is >> inputNotBefore;
                if (inputNotBefore != boost::posix_time::ptime() ) {
                    std::cout << "used " << inputs[i] << " to process " << inputNotBefore << std::endl;
                    failedLookup=false;
                    break;
                }
            }

        }

        return inputNotBefore;
    }

    boost::posix_time::ptime getEndDate(const variables_map& options_map ) {
        boost::posix_time::ptime inputNotAfter;

        if (options_map.count("enddate")) {
            std::string inputNotAfterStr = options_map["enddate"].as<std::string>();

            const char* inputs[] = {
                "%y%m%d%H%M%SZ",
                "%y%m%d%H%M%S",
                "%m/%d/%Y",
                "%Y%m%d%H%M%S",
                "%Y-%m-%d %H:%M:%S%Q",
                "%Y%m%d%H%M",
                "%a %b %d %H:%M:%S UTC %Y",
                "%Y%m%d"
            };
            const size_t formats = sizeof(inputs)/sizeof(inputs[0]);

            bool failedLookup=true;
            for (size_t i=0; i<formats; i++) {
                std::locale testLocale(std::locale::classic(), 
                                       new boost::posix_time::time_input_facet(inputs[i]));
                std::istringstream is(inputNotAfterStr);
                is.imbue(testLocale);
                is >> inputNotAfter;
                if (inputNotAfter != boost::posix_time::ptime() ) {
                    std::cout << "used " << inputs[i] << " to process " << inputNotAfter << std::endl;
                    failedLookup=false;
                    break;
                }
            }
            if (failedLookup) {
                inputNotAfter = boost::posix_time::second_clock::universal_time(); 
            }
        }
        if (options_map.count("days")) {
            boost::posix_time::ptime beginDate = getBeginDate(options_map);
            unsigned int days = options_map["days"].as<unsigned int>();
            inputNotAfter = beginDate + boost::gregorian::days(days);
        }
        if (options_map.count("years")) {
            boost::posix_time::ptime beginDate = getBeginDate(options_map);
            unsigned int years = options_map["years"].as<unsigned int>();
            inputNotAfter = beginDate + boost::gregorian::years(years);
        }
 
        return inputNotAfter;
    }

}   // end anonymous namespace

