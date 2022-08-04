""" Skrypt do testowania """

from pycamp_02_password_checker import LenValidator, LowerValidator, UpperValidator, NumberValidator, SpecialChrValidator, HaveBeenPwnedValidator, AllValidator, NotPass
from pytest import raises


def test_LenValidator_positive():
    test_password = LenValidator('12345678')
    result = test_password.checker()
    assert result is None


def test_LenValidator_negative():
    with raises(NotPass) as e:
        test_password = LenValidator('123')
        test_password.checker()
    assert e.type == NotPass


def test_LowerValidator_positive():
    test_password = LowerValidator('ABCd123')
    result = test_password.checker()
    assert result is None


def test_LowerValidator_negative():
    with raises(NotPass) as e:
        test_password = LowerValidator('ABCD123')
        test_password.checker()
    assert e.type == NotPass


def test_UpperValidator_positive():
    test_password = UpperValidator('abcD123')
    result = test_password.checker()
    assert result is None


def test_UpperValidator_negative():
    with raises(NotPass) as e:
        test_password = UpperValidator('abcd123')
        test_password.checker()
    assert e.type == NotPass


def test_NumberValidator_positive():
    test_password = NumberValidator('abcd123')
    result = test_password.checker()
    assert result is None


def test_NumberValidator_negative():
    with raises(NotPass) as e:
        test_password = NumberValidator('abcd')
        test_password.checker()
    assert e.type == NotPass


def test_SpecialChrValidator_positive():
    test_password = SpecialChrValidator('ABC#123')
    result = test_password.checker()
    assert result is None


def test_SpecialChrValidator_negative():
    with raises(NotPass) as e:
        test_password = SpecialChrValidator('ABCD123')
        test_password.checker()
    assert e.type == NotPass


def test_HaveBeenPwnedValidator_positive():
    test_password = HaveBeenPwnedValidator('aWdR4%6&')
    result = test_password.checker()
    assert result is None


def test_HaveBeenPwnedValidator_negative():
    with raises(NotPass) as e:
        test_password = HaveBeenPwnedValidator('qwerty')
        test_password.checker()
    assert e.type == NotPass
