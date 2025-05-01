import java.security.MessageDigest
import scala.collection.mutable
import java.util.concurrent.{ExecutorService, Executors}
import scala.annotation.tailrec
import scala.util.{Failure, Random, Success, Try, Using}
import scala.concurrent.{Await, ExecutionContext, Future}
import scala.concurrent.duration.*

// Instructor Example Times
// Sequential: Found 83 passwords of length 4 in 921.411 seconds
// Parallel:   Found 83 passwords of length 4 in 151.388 seconds (8-core CPU)

given ExecutionContext = ExecutionContext.global

val NUMCORES = 7;

@main def crackPasswords(): Unit = {
  // load password hashes from the starter pack
  val hashes: Set[String] = getHashes
  // define some character sets to test against the hashes
  val digits = "0123456789"
  val lowercase = "abcdefghijklmnopqrstuvwxyz"
  val uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
  val symbols = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"
  val fullCharset = lowercase + uppercase + digits + symbols
  // try brute forcing all passwords of a specific length n
  val length = 4
  //  val passwords = bruteForceCollection(fullCharset, length, hashes)
  //  println(s"One Character Passwords: ${passwords.mkString(", ")}")

  /*println(s"4 Character Passwords: ")
  val (parTime, parAnswer) = timeIt(bruteForceLoopPar(fullCharset, length, hashes))
  println()
  println(s"Took ${parTime} ms")*/

  val usedCharset = lowercase + uppercase + digits
  Await.ready(parallelRun(usedCharset, 5, hashes), Duration.Inf)

  println()
  println("Finished Running")
  // note that the getCombination function could also be used to combine words . . .
  /*val words = Vector("correct", "horse", "battery", "staple")
  println(getCombination(words)(2)(BigInt(7)).mkString)*/
}

// brute force try every order of chars in charset with replacement using collection methods
def bruteForceCollection(charset: String, length: Int, hashes: Set[String]): Iterable[String] = {
  // identify the range of BigInt that correspond to possible passwords
  val start = BigInt(0)
  val stop = BigInt(charset.length).pow(length)
  // partially apply getCombination to get a simpler function
  val makeCombination = getCombination(charset)(length)
  // use collection methods on a range of BigInts to find possible passwords and filter for ones with matching hashes
  (start until stop).view
    .map((x: BigInt) => makeCombination(x).mkString)
    .filter((pwd: String) => hashes contains sha256(pwd))
}

// brute force try every order of chars in charset with replacement using a for loop
// NOTE: this one might be an easier starting point for futures and doesn't have issues with Int.MaxValue
def bruteForceLoop(charset: String, length: Int, hashes: Set[String]): Iterable[String] = {
  val start = BigInt(0)
  val stop = BigInt(charset.length).pow(length)
  // create a partially applied version of get combination with symbols and length filled in
  val makeCombination = getCombination(charset)(length)
  // create a buffer to hold passwords that have been identified
  val passwords = mutable.ArrayBuffer[String]()
  // loop from the first possible password with this charset to the last checking each
  var cursor = start
  while cursor < stop do {
    // identify the password that goes with this particular number
    val password = makeCombination(cursor).mkString
    // if this password's hash is in the set, add the password to the output list of passwords
    if hashes contains sha256(password) then passwords.addOne(password)
    // increment the cursor
    cursor += 1
  }
  // convert the buffer to an immutable vector and return it
  passwords.toVector
}

// brute force try every order of chars in charset with replacement using a for loop
// NOTE: this one might be an easier starting point for futures and doesn't have issues with Int.MaxValue
def bruteForceLoopPar(charset: String, length: Int, hashes: Set[String]): Unit = {
  val start = BigInt(0)
  val stop = BigInt(charset.length).pow(length)
  // create a partially applied version of get combination with symbols and length filled in
  val makeCombination = getCombination(charset)(length)
  // create a buffer to hold passwords that have been identified
  val passwords = mutable.ArrayBuffer[String]()
  // loop from the first possible password with this charset to the last checking each
  var cursor = start
  while cursor < stop do {
    // identify the password that goes with this particular number
    val password = Future {makeCombination(cursor).mkString}
    // if this password's hash is in the set, print password

    val result = Await.result(password, Duration.Inf)
    if hashes contains sha256(result) then print(s"$result ")
    // increment the cursor
    cursor += 1
  }
  // convert the buffer to an immutable vector and return it
  passwords.toVector
}

def parallelRun(charset: String, length: Int, hashes: Set[String]): Future[Unit] = Future {

  val otherResult = bruteForceMod(charset.substring((charset.length / (NUMCORES - 1)) * (NUMCORES-1), Math.min((charset.length / (NUMCORES - 1)) * (NUMCORES), charset.length)), charset, length - 1, hashes)

  val results = for i <- 0 until NUMCORES-1 yield (
    bruteForceMod(charset.substring((charset.length/(NUMCORES-1))*i, Math.min((charset.length/(NUMCORES-1))*(i+1), charset.length)), charset, length-1, hashes)
    )
  //println("set up futures, awating results:")
  //val otherResult = bruteForceMod(charset.substring((charset.length / (NUMCORES - 1)) * (NUMCORES-1), Math.min((charset.length / (NUMCORES - 1)) * (NUMCORES), charset.length)), charset, length - 1, hashes)
  Await.ready(otherResult, Duration.Inf)
  for i <- results do Await.ready(i, Duration.Inf)
}

def bruteForceMod(beginset: String, charset: String, length: Int, hashes: Set[String]): Future[Unit] = Future {
  println(beginset)

  for i <- beginset do recursiveFor(i.toString, charset, length, hashes)
}

def recursiveFor(stringSoFar: String, charset: String, length: Int, hashes: Set[String]): Unit = {
  if (length == 0) {
    if hashes contains sha256(stringSoFar) then print(s"$stringSoFar ")
  }
  else {
    for char <- charset do recursiveFor(stringSoFar + char, charset, length-1, hashes)
  }
}

// compute the SHA-256 hash of the string using Java's message digest tools
def sha256(text: String): String = {
  MessageDigest.getInstance("SHA-256")
    .digest(text.getBytes("UTF-8"))
    .map("%02x".format(_)).mkString.toUpperCase
}

/**
 * Converts a BigInt into a number in base symbols.size where symbols are the digits.
 * These conversions are restricted by length (number of digits) and include the
 * equivalent of leading zeros to better match the application.
 *
 * @param symbols - the symbols in this base (IndexedSeq for efficient index lookup)
 * @param length -  the number of 'digits' in the output symbol sequence
 * @param index - the number to be converted into a set of symbols in base symbols.size
 * @tparam A    - the type of the symbols (often but not necessarily characters)
 * @return      - a sequence of length possibly repeating items from the symbols unique by index
 */
def getCombination[A](symbols: IndexedSeq[A])(length: Int)(index: BigInt): Seq[A] = {
  // check that the input is in range
  if index < BigInt(0) || index >= BigInt(symbols.size).pow(length) then {
    throw new IndexOutOfBoundsException("Symbol sequence index out of range")
  }
  // create a number buffer to track what symbol comes next
  var numBuffer: BigInt = new BigInt(index.bigInteger)
  // create an output array of items of type A
  val out = mutable.ArrayBuffer[A]()
  // fill the output based on the values of the buffer
  for i <- 0 until length do {
    // interpret the lowest portion of the number as the next symbol
    val next = symbols(numBuffer.mod(symbols.size).toInt)
    out.addOne(next)
    // remove that portion with integer division
    numBuffer /= symbols.size
  }
  // return the updated output buffer as a vector
  out.toVector
}

/**
 * Returns both the answer and the clock time required to compute it for any expression
 *
 * @param f the expression to be executed
 * @tparam A the type to which f evaluates
 * @return the time to compute and value of f
 */
def timeIt[A](f: => A): (Double, A) = {
  val startTime = System.currentTimeMillis()
  val result = f
  val endTime = System.currentTimeMillis()
  (endTime-startTime, result)
}

// loads a set of password hashes from the provided hashes.txt file
def getHashes: Set[String] = {
  val src = io.Source.fromInputStream(
    getClass.getClassLoader.getResourceAsStream("hashes.txt"))
  try {
    src.getLines().toSet
  } finally {
    src.close()
  }
}
