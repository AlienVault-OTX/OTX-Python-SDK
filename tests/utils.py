import random
import string


def generate_rand_string(length=12, charset=string.ascii_lowercase):
    """ Generate a random string with length `length`
    :param charset: possible characters in generated string
    :param length: length of string to return

    :return string
    """
    return ''.join(random.choice(charset) for _ in range(length))
