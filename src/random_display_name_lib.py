"""A module for creating random display names like "Super Blanket"."""

import random

adjectives = ['Best', 'Better', 'Big', 'Blue', 'Brilliant', 'Clear', 'Close', 'Cold', 'Common', 'Current', 'Different', 'Difficult', 'Early', 'Easy', 'Economic', 'Environmental', 'Fancy', 'Final', 'Financial', 'Fine', 'First', 'Fourth', 'Free', 'Full', 'General', 'Good', 'Great', 'Green', 'Happy', 'Hot', 'Human', 'Important', 'Large', 'Late', 'Left', 'Likely', 'Little', 'Long', 'Main', 'Major', 'Medical', 'Natural', 'New', 'Nice', 'Old', 'Open', 'Other', 'Past', 'Political', 'Popular', 'Purple', 'Puzzling', 'Ready', 'Real', 'Red', 'Right', 'Second', 'Serious', 'Short', 'Significant', 'Simple', 'Small', 'Social', 'Special', 'Strong', 'Third', 'True', 'Yellow']

nouns = ['Apple', 'Blanket', 'Box', 'Car', 'Cat', 'Chicken', 'Director', 'Dog', 'Dolphin', 'Duck', 'Eye', 'Face', 'Friend', 'Game', 'Goat', 'Goose', 'Hat', 'Jacket', 'Jeans', 'Ketchup', 'Kid', 'Mouse', 'Noodles', 'Orange', 'Pear', 'Person', 'Plum', 'Shirt', 'Shoe', 'Sock', 'Team', 'Tiger', 'Turtle', 'Zombie']

def random_name():
  return '{} {}'.format(random.choice(adjectives), random.choice(nouns))

if __name__ == '__main__':
  print len(adjectives) * len(nouns), 'possible names'
  for _ in xrange(40):
    print random_name()
