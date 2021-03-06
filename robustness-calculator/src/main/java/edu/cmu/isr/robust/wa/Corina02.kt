/*
 * MIT License
 *
 * Copyright (c) 2020 Changjian Zhang
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 */

package edu.cmu.isr.robust.wa

import edu.cmu.isr.robust.ltsa.*
import edu.cmu.isr.robust.util.SimpleTransitions
import edu.cmu.isr.robust.util.StateMachine

class Corina02(sys: String, env: String, p: String) : AbstractWAGenerator(sys, env, p) {
  /**
   *
   */
  private val alphabetR: Set<String>

  init {
    // Generate alphabets
    val ltsaCall = LTSACall()

    val envComposite = ltsaCall.doCompile(env, "ENV").doCompose()
    println("Environment LTS: ${envComposite.composition.maxStates} states and ${envComposite.composition.ntransitions()} transitions.")
    val alphabetENV = envComposite.alphabetSet()

    val sysComposite = ltsaCall.doCompile(sys, "SYS").doCompose()
    println("System LTS: ${sysComposite.composition.maxStates} states and ${sysComposite.composition.ntransitions()} transitions.")
    val alphabetSYS = sysComposite.alphabetSet()

//    val alphabetP = ltsaCall.doCompile(p, "P").alphabetSet()
//    val alphabetC = alphabetSYS intersect alphabetENV
//    val alphabetI = alphabetSYS - alphabetC
//    alphabetR = (alphabetC + (alphabetP - alphabetI))
    alphabetR = alphabetSYS intersect alphabetENV
  }

  /**
   * Return the alphabet of the weakest assumption
   */
  override fun alphabetOfWA(): Iterable<String> {
    return alphabetR
  }

  override fun weakestAssumption(name: String): String {
    return weakestAssumption(name, false)
  }

  /**
   * Return the LTSA spec representing the weakest assumption of the env.
   */
  fun weakestAssumption(name: String, sink: Boolean): String {
    return composeSysP().pruneError().determinate(sink).minimize().buildFSP(name)
  }

  /**
   *
   */
  private fun composeSysP(): StateMachine {
    val ltsaCall = LTSACall()
    val spec = combineSpecs(sys, p, "||C = (SYS || P)@{${alphabetR.joinToString(",")}}.")

    // Compose and minimise
    val composite = ltsaCall.doCompile(spec, "C").doCompose().minimise()

    if (!composite.composition.hasERROR())
      println("The error state is not reachable. The property is true under any permitted environment.")

    // Get the composed state machine
    return StateMachine(composite)
  }

  /**
   *
   */
  private fun StateMachine.pruneError(): StateMachine {
    var trans = this.transitions
    // Prune the states where the environment cannot prevent the error state from being entered
    // via one or more tau steps.
    while (true) {
      val s = trans.inTrans()[-1]?.find { it.second == this.tau } ?: break
      if (s.first == 0) {
        throw Error("Initial state becomes the error state, no environment can prevent the system from reaching error state")
      }
      trans = SimpleTransitions(trans.allTrans()
          .filter { it.first != s.first }
          .map { if (it.third == s.first) it.copy(third = -1) else it })
    }
    // Eliminate the states that are not backward reachable from the error state
    // FIXME: The Corina02 paper describes this step to remove the unreachable states. However, in the therac25 example,
    // hPressB will lead to "deadlock" (fire forever) and thus will be removed. It results in no hPressB event in the
    // weakest assumption. For now, we remove this step!
//    val reachable = this.getBackwardReachable(setOf(-1))
//    trans = SimpleTransitions(trans.allTrans().filter { it.first in reachable && it.third in reachable })

    return StateMachine(trans, this.alphabet)
  }

  /**
   *
   */
  private fun StateMachine.determinate(sink: Boolean): StateMachine {
    // tau elimination ans subset construction
    val (dfa, dfaStates) = this.tauElmAndSubsetConstr()
    // make sink state
    val dfaSink = if (sink) dfa.makeSinkState(dfaStates) else dfa
    // delete all error states
    return dfaSink.deleteErrors(dfaStates)
  }

  /**
   *
   */
  private fun StateMachine.makeSinkState(dfaStates: List<Set<Int>>): StateMachine {
    val newTrans = this.transitions.allTrans().toMutableSet()
    val alphabetIdx = this.alphabet.indices.filter { it != this.tau }
    val theta = dfaStates.size
    for (s in dfaStates.indices) {
      for (a in alphabetIdx) {
        if (this.transitions.nextStates(s, a).isEmpty()) {
          newTrans.add(Triple(s, a, theta))
        }
      }
    }
    for (a in alphabetIdx) {
      newTrans.add(Triple(theta, a, theta))
    }
    return StateMachine(SimpleTransitions(newTrans), this.alphabet)
  }

  /**
   *
   */
  private fun StateMachine.deleteErrors(dfaStates: List<Set<Int>>): StateMachine {
    val errStates = dfaStates.indices.filter { dfaStates[it].contains(-1) }
    val trans = this.transitions.allTrans().filter { it.first !in errStates && it.third !in errStates }
    return StateMachine(SimpleTransitions(trans), this.alphabet)
  }
}