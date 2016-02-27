class EnglishDetect:
    def __init__(self):
        self.letterFrequencyNums = {}
        lfreq = 'LFrequency.txt'
        charFreq = open(lfreq)
        self.letterFrequencyNums = [i.strip().split() for i in charFreq.readlines()]
        charFreq.close()
        self.letterFrequencyNums = dict(self.letterFrequencyNums)
        for key in self.letterFrequencyNums:
            self.letterFrequencyNums[key] = float(self.letterFrequencyNums[key])

    def scoreCheck(self, string):
        noCharacterPenalty = 50
        totaldelta = 0
        for char in string:
            char = char.lower()
            found = 0
            if (char in self.letterFrequencyNums):
                totaldelta += self.letterFrequencyNums.get(char)
                found = 1
            elif char == " ":
                totaldelta += 10
                found = 1
            elif char > 31 and char < 127:
                totaldelta += .5
                found == 1
            if found == 0:
                totaldelta -= noCharacterPenalty
        totaldelta /= len(string)
        return totaldelta
