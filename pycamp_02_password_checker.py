""" Skrypt sprawdzający moc potencjalnego hasła """


from abc import ABC, abstractmethod
from re import search
from sys import argv
from sys import exit as sysexit
import logging
from hashlib import sha1
from requests import get


class Validator(ABC):
    """ Klasa abstrakcyjna dla każdego z walidatorów """

    def __init__(self, pass_plaintext):
        """ Inicjator walidatora """
        self.pass_plaintext = pass_plaintext

    @abstractmethod
    def checker(self):
        """ Sprawdzany warunek """


class LenValidator(Validator):
    """ Klasa pojedyńczego walidatora sprawdzająca wymaganą ilość znaków """

    def checker(self):
        """ Sprawdzany warunek długości """
        if not len(self.pass_plaintext) >= 8:
            raise NotPass("Hasło nie jest wystarczająco długie! Powinno zawierać conajmniej 8 znaków.")


class LowerValidator(Validator):
    """ Klasa pojedyńczego walidatora sprawdzająca obecność małej litery """

    def checker(self):
        """ Sprawdzany warunek """
        if not search(r'[a-z]+', self.pass_plaintext):
            raise NotPass("Hasło nie zawiera żadnej małej litery! Powinno zawierać conajmniej jedną.")


class UpperValidator(Validator):
    """ Klasa pojedyńczego walidatora sprawdzająca obecność dużej litery """

    def checker(self):
        """ Sprawdzany warunek """
        if not search(r'[A-Z]+', self.pass_plaintext):
            raise NotPass("Hasło nie zawiera żadnej dużej litery! Powinno zawierać conajmniej jedną.")


class NumberValidator(Validator):
    """ Klasa pojedyńczego walidatora sprawdzająca obecność cyfry """

    def checker(self):
        """ Sprawdzany warunek """
        if not search(r'[0-9]+', self.pass_plaintext):
            raise NotPass("Hasło nie zawiera żadnej cyfry! Powinno zawierać conajmniej jedną.")


class SpecialChrValidator(Validator):
    """ Klasa pojedyńczego walidatora sprawdzająca obecność znaku specjalnego """

    def checker(self):
        """ Sprawdzany warunek """
        if not search(r'[!, @, #, $, %, ^, &, *, ?]+', self.pass_plaintext):
            raise NotPass("Hasło nie zawiera żadnego znaku specjalnego! Powinno zawierać conajmniej jednen.")


class HaveBeenPwnedValidator(Validator):
    """ Klasa pojedyńczego walidatora sprawdzająca czy hasło wyciekło - api https://haveibeenpwned.com/ """

    def checker(self):
        """ Sprawdzany warunek """
        pass_hash = sha1(self.pass_plaintext.encode('utf-8')).hexdigest().upper()
        api_response = get('https://api.pwnedpasswords.com/range/' + pass_hash[:5])

        for line in api_response.text.splitlines():
            hash_form_api, _ = line.split(':')
            if pass_hash[5:] == hash_form_api:
                raise NotPass("Haslo wyciekło!")


class AllValidator(Validator):
    """ Klasa sprawdzająca hasło wszystkimi walidatorami """

    def checker(self):
        """ Sprawdzany warunek """
        for one_validator in VALIDATORS:
            validator = one_validator(self.pass_plaintext)
            validator.checker()


class Logger():
    """ Klasa odpowiedzialna za logi """
    log_file = __file__ + '.log'
    log_format = '%(asctime)s - [%(levelname)s] - %(message)s'
    log_date_format = '%Y-%m-%d %H:%M:%S'
    logging.basicConfig(filename=log_file, encoding='utf-8', level=logging.INFO, format=log_format, datefmt=log_date_format)


class NotPass(Exception):
    """ Klasa wyjątku obsługojąca niespełnienie wymogów pojedyńczego walidatora """


VALIDATORS = [LenValidator, LowerValidator, UpperValidator, NumberValidator, SpecialChrValidator, HaveBeenPwnedValidator]


if __name__ == '__main__':

    arg = argv[1]

    pass_to_check = AllValidator(arg)
    try:
        pass_to_check.checker()
        logging.info('Pykło')
    except NotPass as exception:
        logging.error(f'Błąd! {exception.__str__()}')
        sysexit(exception)
