name := "ed25519"

scalaVersion  in ThisBuild := "2.12.8"
scalacOptions in ThisBuild += "-target:jvm-1.8"
javacOptions  in ThisBuild ++= Seq("-source", "1.8", "-target", "1.8")

// Enables publishing to maven repo
publishMavenStyle := true

// Do not append Scala versions to the generated artifacts
crossPaths := false

// This forbids including Scala related libraries into the dependency
//autoScalaLibrary := false

val versions = new {
  val spongy = "1.58.0.0"
  val hamcrest = "1.3"
  val novocode = "0.11"
}

libraryDependencies ++=
  Seq(
    "com.madgag.spongycastle" % "core"           % versions.spongy,
    "com.madgag.spongycastle" % "bcpkix-jdk15on" % versions.spongy,

    "org.hamcrest" % "hamcrest-all"    % versions.hamcrest % "test->default",
    "com.novocode" % "junit-interface" % versions.novocode % "test->default",
  )

git.remoteRepo