# name: discourse-migratepassword
# about: enable alternative password hashes
# version: 0.71
# authors: Jens Maier and Michael@discoursehosting.com
# url: https://github.com/discoursehosting/discourse-migratepassword

# Usage:
# When migrating, store a custom field with the user containing the crypted password

#This will be applied at runtime, as authentication is attempted.  It does not apply at migration time.


gem 'unix-crypt', '1.3.0', :require_name => 'unix_crypt'

enabled_site_setting :migratepassword_enabled

require 'digest'


after_initialize do

    module ::AlternativePassword
        def confirm_password?(password)
            return true if super
            return false unless SiteSetting.migratepassword_enabled
            return false unless self.custom_fields.has_key?('import_pass')

            if AlternativePassword::check_all(password, self.custom_fields['import_pass'])
                self.password = password
                self.custom_fields.delete('import_pass')

                if SiteSetting.migratepassword_allow_insecure_passwords
                    return save(validate: false)
                else
                    return save
                end
            end
            false
        end

        def self.check_all(password, crypted_pass)
            AlternativePassword::check_md5(password, crypted_pass) ||
            AlternativePassword::check_sha1(password, crypted_pass) ||
            AlternativePassword::check_unixcrypt(password, crypted_pass)
        end

        def self.check_md5(password, crypted_pass)
            crypted_pass == Digest::MD5.hexdigest(password)
        end

        def self.check_sha1(password, crypted_pass)
            crypted_pass == Digest::SHA1.hexdigest(password)
        end

        def self.check_unixcrypt(password, crypted_pass)
            UnixCrypt.valid?(password, crypted_pass)
        end
    end

    class ::User
        prepend AlternativePassword
    end

end
