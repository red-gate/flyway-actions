const pluralize = (word: string, count?: number): string => {
  let wordBreakdown;
  switch (true) {
    case endsWithVowelAndY(word):
      wordBreakdown = {
        stem: word,
        singularSuffix: "",
        pluralSuffix: "s",
      };
      break;
    case word.endsWith("y"):
      wordBreakdown = {
        stem: word.substring(0, word.length - 1),
        singularSuffix: "y",
        pluralSuffix: "ies",
      };
      break;
    case word.endsWith("x"):
      wordBreakdown = {
        stem: word.substring(0, word.length - 1),
        singularSuffix: "x",
        pluralSuffix: "xes",
      };
      break;
    case word.endsWith("s"):
      wordBreakdown = {
        stem: word.substring(0, word.length - 1),
        singularSuffix: "s",
        pluralSuffix: "s",
      };
      break;
    default:
      wordBreakdown = { stem: word, singularSuffix: "", pluralSuffix: "s" };
  }

  if (count !== undefined) {
    return `${count} ${wordBreakdown.stem}${count === 1 ? wordBreakdown.singularSuffix : wordBreakdown.pluralSuffix}`;
  }
  return `${wordBreakdown.stem}${wordBreakdown.pluralSuffix}`;
};

const endsWithVowelAndY = (str: string): boolean => /(^|[aeiou\s\W\d_])y$/i.test(str);

export { pluralize };
