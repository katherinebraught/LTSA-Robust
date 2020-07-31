package edu.cmu.isr.robust.fuzz

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

class PhenoFuzzTest {

  @Test
  fun testFuzzBasic() {
    val fuzz = PhenoFuzz("ENV = (a -> (c -> d -> ENV | b -> (c -> ENV | e -> d -> ENV)) | c -> a -> b -> ENV).")
    assertEquals(listOf(
            "a",
            "a,c",
            "a,c,d",
            "a,b",
            "a,b,c",
            "a,b,e",
            "c",
            "c,a",
            "c,a,b"
    ).map { it.split(",") }, fuzz.traceIter(K = 3).asSequence().toList())
  }

  @Test
  fun testFuzzDeadlock() {
    val fuzz = PhenoFuzz("ENV = (a -> (c -> d -> ENV | b -> (c -> ENV | e -> d -> ENV)) | c -> a -> END).")
    assertEquals(listOf(
            "a",
            "a,c",
            "a,c,d",
            "a,b",
            "a,b,c",
            "a,b,e",
            "c",
            "c,a"
    ).map { it.split(",") }, fuzz.traceIter(K = 3).asSequence().toList())
  }


  @Test
  fun createMutationCoffee() {
    val fuzz = PhenoFuzz( "ENV = (hPlaceMug -> ENV_9 | hLiftHandle -> ENV_1),\n" +
            "                ENV_1 = (hPlaceMug -> ENV_8 | hAddOrReplacePod -> ENV_2),\n" +
            "                ENV_2 = (hPlaceMug -> ENV_4 | hLowerHandle -> ENV_3),\n" +
            "                ENV_3 = (hPlaceMug -> ENV_5 | hLiftHandle -> ENV_2),\n" +
            "                ENV_4 = (hLowerHandle -> ENV_5),\n" +
            "                ENV_5 = (hLiftHandle -> ENV_4 | hPressBrew -> ENV_6),\n" +
            "                ENV_6 = (mBrewDone -> ENV_7),\n" +
            "                ENV_7 = (hTakeMug -> ENV),\n" +
            "                ENV_8 = (hAddOrReplacePod -> ENV_4),\n" +
            "                ENV_9 = (hLiftHandle -> ENV_8).")

    val results = fuzz.mutationIter(listOf("hLiftHandle", "hPlaceMug", "hAddOrReplacePod", "hLowerHandle", "hPressBrew", "mBrewDone"))

    println(results.next())
    println(results.next())
    println(results.next())
    println(results.next())
    println(results.next())


  }
}