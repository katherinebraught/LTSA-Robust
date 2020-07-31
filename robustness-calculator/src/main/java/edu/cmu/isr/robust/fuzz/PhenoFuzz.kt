package edu.cmu.isr.robust.fuzz

import edu.cmu.isr.robust.ltsa.*
import edu.cmu.isr.robust.util.StateMachine
import edu.cmu.isr.robust.util.Transition
import java.util.*

class PhenoFuzz(val env: String) {

  private val envModel = StateMachine(LTSACall.doCompile(env, "ENV").doCompose())

  val phenotypes = listOf<Pair<String, List<String>>>(Pair("omission", listOf("s1", "o_a", "s2")),
          Pair("jump_forward", listOf("s1", "o_s2", "s3")),
          Pair("jump_backward", listOf("s1", "s2", "i_s2","s3")),
          Pair("repetition", listOf("s1", "a1", "i_a1+","s3")),
          Pair("intrusion", listOf("s1", "i_s2 ", "s3")),
          Pair("recovery", listOf("s1", "o_s4", "s2", "i_s4", "s3")),
          Pair("reversal", listOf("s1", "o_s2", "i_rs2", "s3")),
          Pair("side_tracking", listOf("s1","s2","s3","o_s4","i_[s2 OR s6]","i_s4","s5","s6","s7")),
          Pair("capture", listOf("s1","s2","s3","o_s4","i_[s2 OR s6]","s5","s6","s7")))

  val MAX_ACTIONS = 20

  var alphabet = envModel.alphabet.subList(1,envModel.alphabet.size)

  /**
   * TODO: Compared to normal model checking:
   *  1. For a muated E', SYS||E' |= P usually only produces the first counterexample
   *  2. Mutation can make E" super huge which makes it impossible to do model checking. On the other hand, we always
   *  do model checking with a mutated **trace**
   *  3. trace-focused not one function
   *  4. black box system model, or a given system behavior model
   *  5. cover the different errors, instead of cover more paths in the code
   * TODO: What are the possible parameters here?
   * TODO: Scalability?
   * TODO: How to avoid mutations which result in the same error trace?
   * TODO: How to fuzz? Completely random? Coverage?
   *
   * @param K the maximal depth to search when generating the normal trace
   */
  fun fuzz(K: Int) {
    for (normTrace in traceIter(K)) {
      println("Pick normal trace: $normTrace")
      for ((phenotype, mutated) in mutationIter(normTrace)) {
        println("Mutate the trace with error type: $phenotype")
        println("Mutated trace: $mutated")
      }
    }
  }

  /**
   * TODO: 1. specify the maximal length of the trace.
   *
   * @author Changjian
   */
  fun traceIter(K: Int): Iterator<List<String>> {
    return TraceIterator(envModel, K)
  }

  /**
   * TODO:
   *  1. all possible error traces for a normal trace
   *  2. FUZZ! we randomly pick one or K from the catalog
   *  3. For a normal trace t, generate mutated traces cover all the actions in t.
   *  4. Coverage for types of errors.
   *  5. For <a, b, c>: avoid <a, e1, c> and <a, e2, c>
   *      Create a record;
   *      normal: <a, b, c, d>, mutated <a, e1, c, d>
   *
   * NOTE to Katherine: I made the return class as an Iterator, which means it does not need to return a whole list
   * of mutated string which might save some memory. So it means that you probably have to build another class
   * which implements the Iterator interface like I did below.
   *  @author Katherine
   */
  //TODO change return type back to an interator
  fun mutationIter(trace: List<String>): Iterable<Pair<String, List<String>>> {
    var results = listOf<Pair<String, List<String>>>()
    var errCnt = 0
    while (errCnt < 5) {
      val error = chooseErrorType(trace.size)
      val partitions = chooseParitions(error.second, trace)

      val errorTrace = generateMutation(trace, error, partitions, alphabet)

      if (errorTrace != null) {
        results += Pair<String, List<String>>(error.first, errorTrace)
        errCnt++
      }

    }

    return results
  }

  /**
  A helper function to choose a random phenotype error.
  Will only choose error if trace is long enough to have all parts

  Trace length is the length of the normal trace
   */
  private fun chooseErrorType(traceLength: Int): Pair<String, List<String>> {
    var phenotype = phenotypes[Random().nextInt(phenotypes.size)]

    while (traceLength < phenotype.second.size ) {
      phenotype = phenotypes[Random().nextInt(phenotypes.size)]
    }
    return phenotype
  }

  private fun chooseParitions(pattern: List<String>, normaltrace: List<String>): List<Int> {

    var partitionsNeeded = 0
    var actionPartition = emptyList<Boolean>()
    for (rule in pattern) {
      if (!rule.contains(Regex("^i_"))) {
        if (rule.contains(Regex("s\\d+"))) {
          partitionsNeeded++
          actionPartition+=false
        }
        else if (rule.contains(Regex("a\\d+"))) {
          actionPartition+=true
        }
      }
    }
    //need 1 less partition because one paritition is the end of the string
    partitionsNeeded-=1



    var valid_partitions = false
    var partitions = listOf<Int>()


    while (!valid_partitions) {
      //generate partitions
      partitions = listOf()

      //special case: ends with an action
      if (actionPartition.last()) {
        actionPartition = actionPartition.subList(0, actionPartition.size -1)
        partitionsNeeded -=1
        partitions+= normaltrace.size -1
      }

      var i = 0
      while (i < partitionsNeeded) {
        partitions += Random().nextInt(normaltrace.size)
        i++
      }
      partitions += normaltrace.size
      //add 0 for ease of checking
      partitions += 0
      partitions = partitions.sorted()

      //println(pattern)
      //println(partitions)
      //println(actionPartition)
      //println("In Loop:")

      //check their value
      valid_partitions = true
      i = 1
      for (needsActionParition in actionPartition) {
        // println("With value $needsActionParition, comparing ${partitions[i]} and ${partitions[i-1]}")
        //if we are check an action parition
        if (needsActionParition) {
          //if we are looking at an action, rather than a set, the previous action should be at least two away from the number at i-1 and i
          if (partitions[i] - partitions[i-1] < 2) {
            valid_partitions = false
            break
          }
        }
        else {
          //check that i-1 is not the same as i
          if (partitions[i] - partitions[i-1] == 0) {
            valid_partitions = false
            break
          }
          i++
        }
      }

    }
    //remove the 0 from the partition list
    return partitions.subList(1, partitions.size)
  }


  /**
   * A method to generate a single mutation based on some error pattern and a set of valid partitions
   *
   * Characters in our pattern language:
   * a - a single action
   * s - a set of actions
   * o_ - the omission of whatever follows the "_"
   * i_ - the insertion of whatever follows the "_"
   *      r - used to indicate that a sequence should be , must be on an insertion - eg. i_rs1
   *      + - indicates an action or series can be added 1 or more times, must follow an insertion - eg. i_a1+
   * numbers - used to specify a particular sequence or action
   *
   * assumes that valid parition values will be passed in. Partition must include the final index but not the 0th index
   */
  private fun generateMutation(normaltrace: List<String>, error: Pair<String, List<String>>, partitons: List<Int>, alphabet: List<String>): List<String>? {
    var ruleMap = mutableMapOf<String, List<String>>()
    var partitionIndex = 0
    var actualPartitions = mutableListOf<Int>(0)
    for (rule in error.second) {
      if (!rule.startsWith("i_")) {

        var name_match = Regex("([as][0-9]*)").find(rule)
        var section_name: String
        if (name_match != null) {
          section_name = name_match.groupValues[1]
        }
        else {
          println("Error: invalid pattern at character $rule")
          return null
        }

        if (section_name.contains(Regex("s[0-9]*"))) {
          //println(actualPartitions.lastIndex)

          ruleMap[section_name] = normaltrace.subList(actualPartitions[actualPartitions.lastIndex],partitons.get(partitionIndex))
          actualPartitions.add(partitons.get(partitionIndex))
          partitionIndex++
        }
        else if (section_name.contains(Regex("a[0-9]*"))) {
          val latestIndex = actualPartitions[actualPartitions.lastIndex]

          ruleMap[section_name] = normaltrace.subList(latestIndex,latestIndex+1)
          actualPartitions.add(latestIndex+1)
        }
      }
    }

    //print(ruleMap)

    var errorString = mutableListOf<String>()
    var errorEncodedString = mutableListOf<String>()
    //build the error strings
    for (rule in error.second) {
      var insertionORrule = rule
      if (rule.contains(Regex("^i_\\[.*OR.*\\]"))) {
        insertionORrule = chooseOr(rule)
      }

      var match = Regex("([as][0-9]*)").find(insertionORrule)
      var mapVal: String
      if (match != null) {
        mapVal = match.groupValues[1]
      } else {
        println("Error: invalid pattern at character $rule")
        return null
      }

      //println(mapVal)

      // insertion
      if (insertionORrule.contains(Regex("^i_.*"))) {

        var toAdd = ruleMap[mapVal]

        //case where can insert anything because this wasn't specified else where
        if (toAdd == null) {
          var max_actions = 1
          if (insertionORrule.contains(Regex(".*s.*"))) {
            max_actions = Random().nextInt(MAX_ACTIONS) + 1
          }
          toAdd = emptyList()
          for (i in 1..max_actions) {
            toAdd+=alphabet[Random().nextInt(alphabet.size-1)]
          }
        }

        //println("found insertion $toAdd")


        if (insertionORrule.contains(Regex("^i_r.*"))) {
          //print("reversal")
          toAdd = toAdd.reversed()
        }
        if (insertionORrule.contains(Regex("^i_.*\\+"))) {
          val temp_add = toAdd
          //TODO: what should the max be?
          val numToAdd = Random().nextInt(MAX_ACTIONS)
          for (i in 0..numToAdd) {
            toAdd+=temp_add
          }
        }

        errorString.addAll(toAdd)
        errorEncodedString.add("error_insertion_${error.first}")
        errorEncodedString.addAll(toAdd)
        errorEncodedString.add("end_error_insertion_${error.first}")



      }
      else if (rule.contains(Regex("^o_.*"))) {
        //println("found omission")
        val toAdd = ruleMap[mapVal]
        if (toAdd!=null) {
          errorEncodedString.add("error_omission_${error.first}_$toAdd")
        }

      }
      else {
        val toAdd = ruleMap[mapVal]
        //println("found regular $toAdd")
        if (toAdd != null) {
          errorString.addAll(toAdd)
          errorEncodedString.addAll(toAdd)
        }
      }


    }

    //returns error trace and normal trace with error transition
    return errorEncodedString
  }

  //must preserve an i_ prefix
  /**
  A helper method to take in a OR sequence and randomly choose which to use
  Pattern is expected to look like i_[s1 OR s2]
   */
  private fun chooseOr(pattern: String): String {
    var choices = pattern.split("OR")
    //println("choosing an or")
    //println(choices)
    var max = choices.size
    val toReturn = choices.get(Random().nextInt(max))
    if (toReturn.startsWith("i_")) {
      return toReturn
    } else {
      return "i_$toReturn"
    }
  }

}

/**
 * Use DFS to iterate over a state machine
 */
private class TraceIterator(val sm: StateMachine, val K: Int): Iterator<List<String>> {

  private val outTrans = sm.transitions.outTrans()
  private val curTrace = LinkedList<String>()
  private val stack: Deque<Iterator<Transition>> = LinkedList()

  init {
    stack.push(outTrans[0]?.iterator()?: emptyList<Transition>().iterator())
  }

  override fun hasNext(): Boolean {
    while (stack.isNotEmpty()) {
      if (stack.peek().hasNext()) {
        return true
      }
      stack.pop()
      if (stack.isNotEmpty())
        curTrace.removeLast()
    }
    return false
  }

  override fun next(): List<String> {
    val curIter = stack.peek()
    val t = curIter.next()
    curTrace.add(sm.alphabet[t.second])
    val copy = curTrace.toList()

    if (stack.size < K)
      stack.push(outTrans[t.third]?.iterator()?: emptyList<Transition>().iterator())
    else
      curTrace.removeLast()

    return copy
  }

}