from slugkit import slugify


def test_basic():
    assert slugify("Hello, World!") == "hello-world"


def test_collapses_separators():
    assert slugify("a  b__c - d") == "a-b-c-d"


def test_accents():
    assert slugify("Crème Brûlée") == "creme-brulee"


def test_max_length_does_not_end_with_hyphen():
    assert slugify("word " * 20, max_length=12) == "word-word"
